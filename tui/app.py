from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Header, Footer, Static, Log, Button, Label
from textual.reactive import reactive
from textual.worker import Worker
import asyncio
import subprocess
import time
import os
from fuzzer.mutator import Mutator
import re
from fuzzer.utils import check_aslr, check_pie, cyclic_find

class StatsWidget(Static):
    execs = reactive(0)
    crashes = reactive(0)
    start_time = reactive(0.0)

    def on_mount(self) -> None:
        self.start_time = time.time()
        self.update_timer = self.set_interval(0.1, self.update_stats)

    def update_stats(self) -> None:
        elapsed = time.time() - self.start_time
        rate = self.execs / elapsed if elapsed > 0 else 0.0
        self.update(f"Execs: {self.execs} | Crashes: {self.crashes} | Rate: {rate:.2f}/s | Time: {elapsed:.2f}s")

class MemSieveApp(App):
    CSS = """
    Screen {
        layout: vertical;
    }
    .box {
        height: 100%;
        border: solid green;
    }
    #sidebar {
        width: 25%;
        dock: left;
        border: solid blue;
    }
    #main {
        width: 75%;
        height: 100%;
        border: solid red;
    }
    Log {
        height: 1fr;
        border: solid white;
    }
    StatsWidget {
        height: 3;
        border: solid yellow;
        text-align: center;
    }
    .banner {
        height: auto;
        text-align: center;
        color: green;
        margin: 0;
        padding: 0;
    }
    #sec_info {
        height: 3;
        text-align: center;
        border: solid white;
    }
    #top_bar {
        height: 3;
    }
    """

    BINDINGS = [("d", "toggle_dark", "Toggle dark mode"), ("q", "quit", "Quit")]

    def __init__(self, target: str, initial_input: str):
        super().__init__()
        self.target = target
        self.initial_input = initial_input.encode() if initial_input else b'A'*10
        self.mutator = Mutator(self.initial_input)
        self.worker: Worker = None
        self.keep_running = False
        
        # Security Checks
        self.aslr_status = check_aslr()
        self.pie_status = check_pie(self.target)

    def compose(self) -> ComposeResult:
        banner_text = r"""
  __  __                  _____ _                  
 |  \/  | ___ _ __ ___   / ____(_) _____   _____   
 | |\/| |/ _ \ '_ ` _ \ | (___ | |/ _ \ \ / / _ \  
 | |  | |  __/ | | | | | \___ \| |  __/\ V /  __/  
 |_|  |_|\___|_| |_| |_| ____/ |_|\___| \_/ \___| v0.1
        """
        yield Static(banner_text, classes="banner")
        
        # Compact stats and security info
        with Horizontal(id="top_bar"):
            yield Static(f"ASLR: {self.aslr_status} | PIE: {self.pie_status}", classes="box", id="sec_info", markup=False)
            yield StatsWidget(id="stats")
        
        with Horizontal():
            with Vertical(id="sidebar"):
                yield Button("Start Fuzzing", id="start", variant="success")
                yield Button("Stop", id="stop", variant="error")
                yield Label(f"Target: {os.path.basename(self.target)}")
            with Vertical(id="main"):
                yield Log(id="log_view", highlight=True)
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "start":
            if not self.keep_running:
                self.keep_running = True
                self.run_fuzzing()
                self.query_one("#log_view").write_line("[+] Fuzzing started...")
                self.query_one("#start").disabled = True
                self.query_one("#stop").disabled = False
        elif event.button.id == "stop":
            self.keep_running = False
            self.query_one("#log_view").write_line("[-] Stopping...")
            self.query_one("#start").disabled = False
            self.query_one("#stop").disabled = True



    def run_fuzzing(self):
        self.worker = self.run_worker(self.fuzz_loop, exclusive=True)

    async def fuzz_loop(self):
        log = self.query_one("#log_view")
        stats = self.query_one("#stats")
        
        tracer_path = "./build/tracer"
        if not os.path.exists(tracer_path):
             log.write_line(f"[!] Tracer not found at {tracer_path}")
             self.keep_running = False
             return

        while self.keep_running:
            payload = self.mutator.mutate()
            
            # Write payload to stderr or a temp file if needed, or pass as arg
            # For this simple tracer, we pass as arg. 
            # BEWARE: shell injection if we used shell=True/system. We execute directly.
            
            try:
                # We need to run the tracer which runs the target
                # Command: ./build/tracer <target> <payload>
                
                # Careful with null bytes in args if passing via argv.
                # Python's subprocess argument passing might choke on null bytes in string.
                # For robust fuzzing, we should write to file or stdin.
                # But our vulnerable app takes argv[1].
                
                safe_payload = payload.replace(b'\x00', b'') # Quick hack for argv
                
                process = await asyncio.create_subprocess_exec(
                    tracer_path, 
                    self.target, 
                    safe_payload.decode('latin-1', errors='ignore'),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await process.communicate()
                
                output = stdout.decode('latin-1', errors='ignore')
                stats.execs += 1
                
                if "CRASH DETECTED" in output:
                    stats.crashes += 1
                    
                    # Extract RIP/EIP
                    rip_match = re.search(r'RIP: (0x[0-9A-Fa-f]+)', output)
                    triage_info = "🟢 LOW (Unknown)"
                    offset_info = ""

                    if rip_match:
                        rip_val = rip_match.group(1)
                        # Check EXPLOITABILITY
                        try:
                            # If RIP is part of our payload
                            rip_bytes = bytes.fromhex(rip_val[2:])
                            rip_bytes_le = rip_bytes[::-1] # Little endian
                            
                            if rip_bytes_le in payload:
                                triage_info = "🔴 HIGH (Control of Instruction Pointer)"
                            elif b'\x00' in rip_bytes:
                                triage_info = "🟡 MEDIUM (Possible Null Deref)"
                            
                            # Check Offset (Cyclic)
                            offset = cyclic_find(rip_val)
                            if offset != -1:
                                offset_info = f" | Offset found at: {offset}"
                                triage_info = "🔴 HIGH (Control of Instruction Pointer)"
                        except:
                            pass

                    log.write_line(f"\n[!] CRASH FOUND! {triage_info}{offset_info}")
                    log.write_line(output)
                    # Create crash file
                    with open(f"crashes/crash_{stats.crashes}.bin", "wb") as f:
                        f.write(payload)
            except Exception as e:
                log.write_line(f"[!] Error: {e}")
            
            # Sleep tiny bit to yield UI? Not needed with await create_subprocess
            # But to prevent freezing logic if too fast
            # await asyncio.sleep(0.001) 

if __name__ == "__main__":
    app = MemSieveApp("./vulnerable_app", "AAAA")
    app.run()
