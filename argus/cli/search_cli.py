"""
CLI search command group for ARGUS.

Provides semantic search across all indexed sources (findings, evidence, CVEs, memory)
with rich table formatting, JSON output, multi-field filtering, and index statistics.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional, Tuple, Union

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
import typer
from typer.core import TyperGroup

from argus.knowledge.cve_kb import CVEKnowledgeBase
from argus.memory.manager import MemoryManager
from argus.vector.models import SearchResult, VectorFilter
from argus.vector.store import VectorStore, get_vector_store

console = Console()


def _get_store(db_path: Optional[str] = None) -> VectorStore:
    """Get global VectorStore or instantiate isolated store when db_path is overridden."""
    if db_path is not None:
        return get_vector_store(db_path=db_path, force_new=True)
    return get_vector_store()


class DefaultTyperGroup(TyperGroup):
    """
    TyperGroup subclass that routes unrecognized commands and option-led invocations
    to a default hidden command ('query'), enabling 'argus search <query>' syntax
    alongside explicit subcommands like 'argus search cves', 'memory', and 'stats'.
    """

    default_cmd_name = "query"

    def parse_args(self, ctx: typer.Context, args: List[str]) -> List[str]:
        if not args:
            args.insert(0, self.default_cmd_name)
        elif any(args[0] == opt for opt in ("--help", "-h")):
            pass
        elif args[0] in self.commands:
            pass
        else:
            args.insert(0, self.default_cmd_name)
        return super().parse_args(ctx, args)


search_app = typer.Typer(
    cls=DefaultTyperGroup,
    help="Semantic search across indexed security findings, evidence, CVEs, and memory.",
    rich_markup_mode="rich",
)


def _extract_title(res_dict: Dict[str, Any]) -> str:
    """Extract or synthesize a concise title for a search result."""
    metadata = res_dict.get("metadata") or {}
    if metadata.get("title"):
        return str(metadata["title"]).strip()
    if metadata.get("cve_id"):
        return str(metadata["cve_id"]).strip()
    if res_dict.get("title"):
        return str(res_dict["title"]).strip()

    # Extract first line from content
    content = str(res_dict.get("content") or "").strip()
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        for prefix in (
            "Finding Title:",
            "Evidence Title:",
            "Title:",
            "Memory Title:",
            "CVE-",
        ):
            if line.startswith(prefix):
                cleaned = line[len(prefix) :].strip()
                if cleaned:
                    return cleaned
        return line[:60]

    return str(res_dict.get("id") or "Result")


def _format_search_results(
    results: List[Dict[str, Any]],
    query: str,
    verbose: bool,
    json_out: bool,
    store: VectorStore,
    custom_title: Optional[str] = None,
) -> None:
    """
    Format and display or serialize search results as Rich table or raw JSON array.
    """
    if json_out:
        output_items = []
        for res in results:
            item: Dict[str, Any] = {
                "id": str(res.get("id", "")),
                "score": round(float(res.get("score", 0.0)), 4),
                "source_type": str(res.get("source_type", "general")),
                "severity": res.get("severity"),
                "category": res.get("category"),
                "mission_id": res.get("mission_id"),
                "title": _extract_title(res),
                "content": str(res.get("content", "")),
                "metadata": res.get("metadata") or {},
                "created_at": str(res.get("created_at", "")),
            }
            if verbose:
                item["embeddings_info"] = {
                    "provider": getattr(
                        store.embedding_engine, "provider_name", "deterministic"
                    ),
                    "dimension": store.dimension,
                    "metric": getattr(
                        store.distance_metric, "value", str(store.distance_metric)
                    ),
                }
            output_items.append(item)

        print(json.dumps(output_items, indent=2))
        return

    # Rich formatted output
    if not results:
        console.print(f"\n[yellow]No results found for query: '{query}'[/yellow]\n")
        return

    header_title = (
        custom_title
        if custom_title
        else f"Vector Search Results: '{query}' ({len(results)} matches)"
    )

    if verbose:
        provider_name = getattr(
            store.embedding_engine, "provider_name", "deterministic"
        )
        metric_name = getattr(
            store.distance_metric, "value", str(store.distance_metric)
        )
        resolved_db = store._get_resolved_path()
        console.print(
            Panel(
                f"[bold]Query:[/bold] [cyan]{query}[/cyan] | "
                f"[bold]Matches:[/bold] [green]{len(results)}[/green] | "
                f"[bold]Provider:[/bold] [yellow]{provider_name}[/yellow] | "
                f"[bold]Dimension:[/bold] {store.dimension} | "
                f"[bold]Metric:[/bold] {metric_name}\n"
                f"[bold]Database:[/bold] {resolved_db}",
                title="🔍 Semantic Search Details",
                border_style="cyan",
                expand=False,
            )
        )

    table = Table(
        title=header_title,
        border_style="dim",
        header_style="bold cyan",
        show_lines=verbose,
    )
    table.add_column("Score", justify="right", style="bold", width=8)
    table.add_column("Type", justify="center", width=10)
    table.add_column("Severity", justify="center", width=10)
    table.add_column("Title / Content", justify="left")
    table.add_column("Category", justify="center", width=16)

    if verbose:
        table.add_column("Mission", justify="center", width=14)
        table.add_column("ID", justify="left", width=22)

    for res in results:
        score_val = float(res.get("score", 0.0))
        if score_val >= 0.7:
            score_str = f"[green]{score_val:.3f}[/green]"
        elif score_val >= 0.4:
            score_str = f"[yellow]{score_val:.3f}[/yellow]"
        else:
            score_str = f"[dim]{score_val:.3f}[/dim]"

        stype = str(res.get("source_type") or "general").lower()
        if stype == "finding":
            type_str = "[magenta]finding[/magenta]"
        elif stype == "cve":
            type_str = "[red]cve[/red]"
        elif stype == "memory":
            type_str = "[cyan]memory[/cyan]"
        elif stype == "evidence":
            type_str = "[blue]evidence[/blue]"
        else:
            type_str = f"[white]{stype}[/white]"

        sev_raw = (res.get("severity") or "-").upper()
        if sev_raw == "CRITICAL":
            sev_str = "[bold red]CRITICAL[/bold red]"
        elif sev_raw == "HIGH":
            sev_str = "[bright_red]HIGH[/bright_red]"
        elif sev_raw == "MEDIUM":
            sev_str = "[yellow]MEDIUM[/yellow]"
        elif sev_raw == "LOW":
            sev_str = "[blue]LOW[/blue]"
        elif sev_raw == "INFO":
            sev_str = "[cyan]INFO[/cyan]"
        else:
            sev_str = "[dim]-[/dim]"

        title_text = _extract_title(res)
        content_text = str(res.get("content") or "").strip()

        if verbose:
            content_snippet = (
                content_text[:200] + "..." if len(content_text) > 200 else content_text
            )
            title_content = f"[bold]{title_text}[/bold]\n[dim]{content_snippet}[/dim]"
        else:
            display_text = title_text if title_text else content_text
            if len(display_text) > 60:
                display_text = display_text[:57] + "..."
            title_content = display_text

        cat_str = str(res.get("category") or "-")

        if verbose:
            mid_str = str(res.get("mission_id") or "-")
            id_str = str(res.get("id") or "-")
            table.add_row(
                score_str,
                type_str,
                sev_str,
                title_content,
                cat_str,
                mid_str,
                id_str,
            )
        else:
            table.add_row(score_str, type_str, sev_str, title_content, cat_str)

    console.print(table)


# ==============================================================================
# 1. Main Search Command ('argus search <query>')
# ==============================================================================


@search_app.command("query", hidden=True)
def search_default(
    query: Optional[str] = typer.Argument(
        None,
        help="Semantic search query across all indexed sources (findings, evidence, CVEs, memory)",
    ),
    type: str = typer.Option(
        "all",
        "--type",
        "-t",
        help="Filter by source type: finding, evidence, cve, memory, or all",
    ),
    severity: Optional[str] = typer.Option(
        None,
        "--severity",
        "-s",
        help="Filter by severity: critical, high, medium, low, info",
    ),
    category: Optional[str] = typer.Option(
        None,
        "--category",
        "-c",
        help="Filter by category",
    ),
    mission: Optional[str] = typer.Option(
        None,
        "--mission",
        "-m",
        help="Filter by mission ID",
    ),
    top_k: int = typer.Option(
        10,
        "--top-k",
        "-k",
        help="Number of results to return (default 10)",
    ),
    min_score: float = typer.Option(
        0.0,
        "--min-score",
        help="Minimum similarity threshold [0.0 - 1.0] (default 0.0)",
    ),
    json_out: bool = typer.Option(
        False,
        "--json",
        help="Output raw JSON array instead of Rich table",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show additional fields (full content, metadata, embeddings info)",
    ),
    db_path: Optional[str] = typer.Option(
        None,
        "--db-path",
        help="Database path override",
        hidden=True,
    ),
) -> None:
    """
    Semantic search across all indexed sources (findings, evidence, CVEs, memory).
    """
    if query is None or not query.strip():
        if json_out:
            print("[]")
            return
        console.print(
            "[bold red]Error:[/bold red] Missing search query. Usage: argus search <query> [OPTIONS]"
        )
        raise typer.Exit(code=1)

    store = _get_store(db_path=db_path)

    filters: Dict[str, Any] = {}
    if type and type.lower() != "all":
        filters["source_type"] = type.lower()
    if severity:
        filters["severity"] = severity.lower()
    if category:
        filters["category"] = category.lower()
    if mission:
        filters["mission_id"] = mission

    raw_results = store.search(
        query=query,
        top_k=top_k,
        filters=filters if filters else None,
        min_score=min_score,
    )

    normalized_results: List[Dict[str, Any]] = []
    for res in raw_results:
        normalized_results.append(
            {
                "id": res.id,
                "score": res.score,
                "source_type": res.source_type,
                "severity": res.severity,
                "category": res.category,
                "mission_id": res.mission_id,
                "title": _extract_title(res.to_dict()),
                "content": res.content,
                "metadata": res.metadata,
                "created_at": res.created_at,
            }
        )

    _format_search_results(
        results=normalized_results,
        query=query,
        verbose=verbose,
        json_out=json_out,
        store=store,
    )


# ==============================================================================
# 2. CVEs Search Shortcut ('argus search cves <query>')
# ==============================================================================


@search_app.command("cves")
def search_cves(
    query: str = typer.Argument(
        ...,
        help="Semantic search query across CVE vulnerability intelligence records",
    ),
    severity: Optional[str] = typer.Option(
        None,
        "--severity",
        "-s",
        help="Filter by severity: critical, high, medium, low, info",
    ),
    category: Optional[str] = typer.Option(
        None,
        "--category",
        "-c",
        help="Filter by category or CWE",
    ),
    cwe: Optional[str] = typer.Option(
        None,
        "--cwe",
        help="Filter by specific CWE taxonomy identifier (e.g. CWE-79, CWE-89)",
    ),
    product: Optional[str] = typer.Option(
        None,
        "--product",
        help="Filter by affected product name or keyword (e.g. Apache, Spring)",
    ),
    mission: Optional[str] = typer.Option(
        None,
        "--mission",
        "-m",
        help="Filter by mission ID",
    ),
    top_k: int = typer.Option(
        10,
        "--top-k",
        "-k",
        help="Number of results to return (default 10)",
    ),
    min_score: float = typer.Option(
        0.0,
        "--min-score",
        help="Minimum similarity threshold [0.0 - 1.0] (default 0.0)",
    ),
    json_out: bool = typer.Option(
        False,
        "--json",
        help="Output raw JSON array instead of Rich table",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show additional fields (full content, metadata, embeddings info)",
    ),
    db_path: Optional[str] = typer.Option(
        None,
        "--db-path",
        help="Database path override",
        hidden=True,
    ),
) -> None:
    """
    Shortcut for CVE-specific semantic search with CWE and affected product filtering.
    """
    store = _get_store(db_path=db_path)
    cve_kb = CVEKnowledgeBase(vector_store=store)

    effective_cwe = cwe or category
    matched_entries = cve_kb.search_cves(
        query=query,
        top_k=top_k,
        min_score=min_score,
        severity=severity,
        cwe=effective_cwe,
        affected_product=product,
    )

    normalized_results: List[Dict[str, Any]] = []
    for entry, score in matched_entries:
        primary_cwe = entry.cwes[0] if entry.cwes else "cve"
        normalized_results.append(
            {
                "id": f"cve:{entry.cve_id}",
                "score": score,
                "source_type": "cve",
                "severity": entry.severity,
                "category": primary_cwe,
                "mission_id": mission,
                "title": entry.title or entry.cve_id,
                "content": entry.description,
                "metadata": {
                    "cve_id": entry.cve_id,
                    "cvss_score": entry.cvss_score,
                    "cvss_vector": entry.cvss_vector,
                    "cwes": entry.cwes,
                    "affected_products": entry.affected_products,
                    "references": entry.references,
                    "published_date": entry.published_date,
                    "last_modified_date": entry.last_modified_date,
                },
                "created_at": entry.published_date or "",
            }
        )

    _format_search_results(
        results=normalized_results,
        query=query,
        verbose=verbose,
        json_out=json_out,
        store=store,
        custom_title=f"CVE Semantic Search: '{query}' ({len(normalized_results)} matches)",
    )


# ==============================================================================
# 3. Memory Search Shortcut ('argus search memory <query>')
# ==============================================================================


@search_app.command("memory")
def search_memory(
    query: str = typer.Argument(
        ...,
        help="Semantic search query across conversational and agentic memories",
    ),
    severity: Optional[str] = typer.Option(
        None,
        "--severity",
        "-s",
        help="Filter by severity",
    ),
    category: Optional[str] = typer.Option(
        None,
        "--category",
        "-c",
        help="Filter by category",
    ),
    memory_type: Optional[str] = typer.Option(
        None,
        "--memory-type",
        help="Filter by memory type: attack_pattern, user_correction, strategic_decision, session_context, note",
    ),
    mission: Optional[str] = typer.Option(
        None,
        "--mission",
        "-m",
        help="Filter by mission ID",
    ),
    top_k: int = typer.Option(
        10,
        "--top-k",
        "-k",
        help="Number of results to return (default 10)",
    ),
    min_score: float = typer.Option(
        0.0,
        "--min-score",
        help="Minimum similarity threshold [0.0 - 1.0] (default 0.0)",
    ),
    json_out: bool = typer.Option(
        False,
        "--json",
        help="Output raw JSON array instead of Rich table",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show additional fields (full content, metadata, embeddings info)",
    ),
    db_path: Optional[str] = typer.Option(
        None,
        "--db-path",
        help="Database path override",
        hidden=True,
    ),
) -> None:
    """
    Shortcut for memory-specific semantic search with memory type filtering.
    """
    store = _get_store(db_path=db_path)
    mem_mgr = MemoryManager(vector_store=store)

    effective_mem_type = memory_type or category

    mem_results = mem_mgr.recall(
        query=query,
        top_k=top_k,
        min_score=min_score,
        mission_id=mission,
        memory_type=effective_mem_type,
    )

    normalized_results: List[Dict[str, Any]] = []
    for res in mem_results:
        sev_val = res.entry.metadata.get("severity") if res.entry.metadata else None
        if severity and sev_val and sev_val.lower() != severity.lower():
            continue

        type_label = (
            res.memory_type.value
            if hasattr(res.memory_type, "value")
            else str(res.memory_type)
        )

        normalized_results.append(
            {
                "id": res.id,
                "score": res.score,
                "source_type": "memory",
                "severity": sev_val,
                "category": type_label,
                "mission_id": res.mission_id,
                "title": res.title,
                "content": res.content,
                "metadata": res.entry.metadata,
                "created_at": res.entry.created_at,
            }
        )

    _format_search_results(
        results=normalized_results,
        query=query,
        verbose=verbose,
        json_out=json_out,
        store=store,
        custom_title=f"Memory Semantic Search: '{query}' ({len(normalized_results)} matches)",
    )


# ==============================================================================
# 4. Search Statistics ('argus search stats')
# ==============================================================================


@search_app.command("stats")
def search_stats(
    json_out: bool = typer.Option(
        False,
        "--json",
        help="Output raw JSON instead of Rich table",
    ),
    db_path: Optional[str] = typer.Option(
        None,
        "--db-path",
        help="Database path override",
        hidden=True,
    ),
) -> None:
    """
    Display index statistics: counts by source_type, total documents, store path, and embedding provider.
    """
    store = _get_store(db_path=db_path)
    total_docs = store.count()
    resolved_path = store._get_resolved_path()
    provider_name = getattr(
        store.embedding_engine, "provider_name", "deterministic"
    )
    dimension = store.dimension
    distance_metric = getattr(
        store.distance_metric, "value", str(store.distance_metric)
    )

    with store._lock:
        cur = store._conn.execute(
            f"SELECT source_type, COUNT(*) as cnt FROM {store.table_name} GROUP BY source_type ORDER BY cnt DESC;"
        )
        raw_counts = {row[0]: row[1] for row in cur.fetchall()}

    counts_by_source_type = {
        "finding": raw_counts.get("finding", 0),
        "evidence": raw_counts.get("evidence", 0),
        "cve": raw_counts.get("cve", 0),
        "memory": raw_counts.get("memory", 0),
    }
    for k, v in raw_counts.items():
        if k not in counts_by_source_type:
            counts_by_source_type[k] = v

    if json_out:
        stats_payload = {
            "total_documents": total_docs,
            "vector_store_path": resolved_path,
            "embedding_provider": provider_name,
            "dimension": dimension,
            "distance_metric": distance_metric,
            "counts_by_source_type": counts_by_source_type,
        }
        print(json.dumps(stats_payload, indent=2))
        return

    # Rich formatted output
    console.print(
        Panel(
            f"[bold]Vector Store Path:[/bold] {resolved_path}\n"
            f"[bold]Total Documents:[/bold]   [green]{total_docs}[/green]\n"
            f"[bold]Embedding Provider:[/bold] [yellow]{provider_name}[/yellow]\n"
            f"[bold]Vector Dimension:[/bold]   {dimension}\n"
            f"[bold]Distance Metric:[/bold]    {distance_metric}",
            title="📊 ARGUS Vector Index Statistics",
            border_style="cyan",
            expand=False,
        )
    )

    table = Table(
        title="Document Counts by Source Type",
        border_style="dim",
        header_style="bold cyan",
    )
    table.add_column("Source Type", style="bold")
    table.add_column("Document Count", justify="right", style="green")

    for stype, cnt in counts_by_source_type.items():
        table.add_row(stype, str(cnt))

    console.print(table)
