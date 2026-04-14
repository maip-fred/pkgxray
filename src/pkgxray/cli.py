"""Interfaz de línea de comandos para pkgxray."""

import click
from rich.console import Console

from pkgxray.downloader import DownloadError, PackageNotFoundError
from pkgxray.reporter import generate_report
from pkgxray.scanner import scan

console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="pkgxray")
def main():
    """pkgxray - Analiza paquetes de PyPI en busca de comportamiento sospechoso antes de instalarlos."""
    pass


@main.command(name="scan")
@click.argument("package_name")
@click.option("--version", "-v", default=None, help="Versión específica del paquete a analizar")
@click.option(
    "--format", "-f", "output_format",
    type=click.Choice(["terminal", "json", "html"]),
    default="terminal",
    help="Formato de salida del reporte",
)
@click.option("--output", "-o", default=None, help="Guardar el reporte en un archivo")
def scan_cmd(package_name, version, output_format, output):
    """Analiza un paquete de PyPI en busca de comportamiento sospechoso."""
    try:
        console.print(f"\n[bold]Analizando [cyan]{package_name}[/cyan]...[/bold]\n")
        result = scan(package_name, version)
        generate_report(result, format=output_format, output_path=output)
        if output:
            console.print(f"\n[bold]Reporte guardado en [green]{output}[/green][/bold]")
    except PackageNotFoundError:
        console.print(f"[red]Error: El paquete '{package_name}' no fue encontrado en PyPI[/red]")
        raise SystemExit(1)
    except DownloadError as e:
        console.print(f"[red]Error al descargar el paquete: {e}[/red]")
        raise SystemExit(1)
    except Exception as e:
        console.print(f"[red]Error inesperado: {e}[/red]")
        raise SystemExit(1)
