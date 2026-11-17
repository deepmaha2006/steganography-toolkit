"""Entry point — allows `python main.py <subcommand>`."""
from stego.cli import cli

if __name__ == "__main__":
    cli(standalone_mode=True)
