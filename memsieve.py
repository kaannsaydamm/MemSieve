import argparse
import sys
import os
import time

# Add current directory to path to find modules
sys.path.append(os.getcwd())

from tui.app import MemSieveApp
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm

console = Console()

def run_wizard():
    console.clear()
    console.print(Panel.fit("[bold green]MemSieve Wizard[/bold green]\n[cyan]Interactive Configuration Mode[/cyan]"))
    
    target = Prompt.ask("[bold yellow]Target Binary Path[/bold yellow]", default="./vulnerable_app")
    while not os.path.exists(target):
        console.print(f"[red]Error: File code{target} not found![/red]")
        target = Prompt.ask("[bold yellow]Target Binary Path[/bold yellow]")

    use_seed_file = Confirm.ask("Do you want to use a seed file?", default=False)
    seed_input = None
    
    if use_seed_file:
        seed_path = Prompt.ask("[bold yellow]Seed File Path[/bold yellow]")
        if os.path.exists(seed_path):
            with open(seed_path, "r") as f:
                seed_input = f.read().strip()
        else:
            console.print("[red]File not found, falling back to default 'AAAA'[/red]")
            seed_input = "AAAA"
    else:
        seed_input = Prompt.ask("[bold yellow]Initial Input String[/bold yellow]", default="AAAA")

    console.print(f"\n[bold green]Configuration Ready![/bold green]")
    console.print(f"Target: [cyan]{target}[/cyan]")
    console.print(f"Seed Length: [cyan]{len(seed_input)}[/cyan]")
    
    if Confirm.ask("Launch MemSieve now?", default=True):
        return target, seed_input
    else:
        console.print("[red]Aborted.[/red]")
        sys.exit(0)

def main():
    parser = argparse.ArgumentParser(
        description="MemSieve: Automated Memory Corruption Fuzzer & Crash Analyzer",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python3 memsieve.py --wizard              # Start interactive wizard
  python3 memsieve.py --target ./vuln       # Fuzz a binary with default settings
  python3 memsieve.py --target ./vuln --input input.txt  # Use a seed file
        """
    )
    
    parser.add_argument("--target", help="Path to the target executable binary")
    parser.add_argument("--input", help="Initial seed input string or path to a file")
    parser.add_argument("--wizard", action="store_true", help="Launch interactive wizard mode")

    args = parser.parse_args()

    # Ensure crashes directory exists
    if not os.path.exists("crashes"):
        os.makedirs("crashes")

    target = args.target
    seed = "A" * 10

    if args.wizard:
        target, seed = run_wizard()
    elif not args.target:
        parser.print_help()
        sys.exit(1)
    else:
        # Standard CLI handling
        if args.input:
            if os.path.exists(args.input):
                with open(args.input, "r") as f:
                    seed = f.read().strip()
            else:
                seed = args.input

    # Check if target exists
    if not os.path.exists(target):
        console.print(f"[bold red]Error: Target binary '{target}' not found![/bold red]")
        sys.exit(1)

    app = MemSieveApp(target, seed)
    app.run()

if __name__ == "__main__":
    main()
