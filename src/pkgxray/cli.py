"""Interfaz de línea de comandos para pkgxray."""

import logging

import click
from rich.console import Console

from pkgxray import __version__
from pkgxray.downloader import DownloadError, PackageNotFoundError
from pkgxray.reporter import generate_report
from pkgxray.scanner import scan

console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="pkgxray")
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
@click.option(
    "--fail-above", type=int, default=None,
    help="Salir con código 1 si el score >= este valor (útil en pipelines CI/CD)",
)
@click.option(
    "--verbose", is_flag=True, default=False,
    help="Mostrar logs de depuración (fallos de analizadores, pasos del pipeline)",
)
@click.option(
    "--index-url", default=None,
    help="URL base del registro PyPI privado (también: env PKGXRAY_INDEX_URL)",
)
def scan_cmd(package_name, version, output_format, output, fail_above, verbose, index_url):
    """Analiza un paquete de PyPI en busca de comportamiento sospechoso."""
    if verbose:
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(levelname)s %(name)s: %(message)s",
        )

    try:
        console.print(f"\n[bold]Analizando [cyan]{package_name}[/cyan]...[/bold]\n")
        result = scan(package_name, version, registry_url=index_url)
        generate_report(result, output_format=output_format, output_path=output)

        if output:
            console.print(f"\n[bold]Reporte guardado en [green]{output}[/green][/bold]")

        if fail_above is not None and result.risk_score >= fail_above:
            console.print(
                f"\n[red bold]Score {result.risk_score} >= umbral {fail_above}"
                f" — saliendo con código 1 (fail-above activado)[/red bold]"
            )
            raise SystemExit(1)

    except PackageNotFoundError:
        console.print(f"[red]Error: El paquete '{package_name}' no fue encontrado en PyPI[/red]")
        raise SystemExit(1)
    except DownloadError as e:
        console.print(f"[red]Error al descargar el paquete: {e}[/red]")
        raise SystemExit(1)
    except SystemExit:
        raise
    except Exception as e:
        console.print(f"[red]Error inesperado: {e}[/red]")
        raise SystemExit(1)


@main.command(name="clear-cache")
def clear_cache_cmd():
    """Elimina todos los resultados del caché persistente en disco."""
    from pkgxray import _disk_cache
    from pkgxray.scanner import clear_cache as clear_session_cache

    n_disk = _disk_cache.clear()
    clear_session_cache()
    console.print(f"[green]Caché eliminado: {n_disk} resultado(s) en disco.[/green]")
