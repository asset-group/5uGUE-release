"""Paper search and knowledge base tools — local 5G paper collection."""

import hashlib
import json
import logging
import os
import re
import time

from constants import (
    LOCAL_PAPERS_PATH,
    PAPERS_INDEX_PATH,
    PAPERS_TEXT_PATH,
)

logger = logging.getLogger(__name__)

# Lazy init flag
_local_papers_indexed = False


def _slugify(filename: str) -> str:
    """Convert a filename to a safe slug for use as paper ID."""
    name = os.path.splitext(filename)[0]
    slug = re.sub(r"[^a-zA-Z0-9_-]", "_", name).strip("_").lower()
    return slug or hashlib.sha256(filename.encode()).hexdigest()[:16]


def _safe_paper_id(paper_id: str) -> str:
    """Make paper_id filesystem-safe (replace colons)."""
    return paper_id.replace(":", "_")


def _load_index() -> list[dict]:
    """Load all entries from the paper index."""
    if not os.path.exists(PAPERS_INDEX_PATH):
        return []
    entries = []
    with open(PAPERS_INDEX_PATH, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return entries


def _get_indexed_ids() -> set:
    """Get set of all paper_ids already in the index."""
    return {e["paper_id"] for e in _load_index()}


def _append_index(entry: dict):
    """Append a single entry to the paper index."""
    with open(PAPERS_INDEX_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")


def _extract_pdf_text(pdf_path: str) -> str:
    """Extract text from a PDF using pypdf."""
    try:
        from pypdf import PdfReader

        reader = PdfReader(pdf_path)
        parts = []
        for page in reader.pages:
            text = page.extract_text()
            if text:
                parts.append(text)
        return "\n".join(parts)
    except Exception as e:
        logger.warning(f"PDF text extraction failed for {pdf_path}: {e}")
        return ""


def _index_local_papers():
    """Walk 5g-papers-main/ and index all PDFs not yet in the index."""
    global _local_papers_indexed
    if _local_papers_indexed:
        return
    _local_papers_indexed = True

    if not os.path.isdir(LOCAL_PAPERS_PATH):
        logger.warning(f"Local papers directory not found: {LOCAL_PAPERS_PATH}")
        return

    existing_ids = _get_indexed_ids()
    indexed_count = 0

    for category_dir in sorted(os.listdir(LOCAL_PAPERS_PATH)):
        category_path = os.path.join(LOCAL_PAPERS_PATH, category_dir)
        if not os.path.isdir(category_path):
            continue

        for filename in sorted(os.listdir(category_path)):
            if not filename.lower().endswith(".pdf"):
                continue

            slug = _slugify(filename)
            paper_id = f"local:{slug}"

            if paper_id in existing_ids:
                continue

            pdf_path = os.path.join(category_path, filename)
            text = _extract_pdf_text(pdf_path)
            text_failed = len(text.strip()) == 0

            # Save extracted text
            if not text_failed:
                text_path = os.path.join(
                    PAPERS_TEXT_PATH, f"{_safe_paper_id(paper_id)}.txt"
                )
                with open(text_path, "w") as f:
                    f.write(text)

            # Derive title from filename
            title_raw = os.path.splitext(filename)[0]
            title = re.sub(r"[_-]", " ", title_raw).strip().title()

            abstract = text[:500] if text else ""

            entry = {
                "paper_id": paper_id,
                "title": title,
                "abstract": abstract,
                "authors": [],
                "category": category_dir,
                "source": "local",
                "pdf_url": "",
                "pdf_path": pdf_path,
                "stored_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "notes": "",
                "text_extraction_failed": text_failed,
            }
            _append_index(entry)
            existing_ids.add(paper_id)
            indexed_count += 1

    if indexed_count > 0:
        logger.info(f"Indexed {indexed_count} local papers from {LOCAL_PAPERS_PATH}")


def get_paper_tools(kb, target_vendor: str, target_protocol: str) -> dict:
    """Build paper research tool registry."""

    # Lazy-index local papers on first call
    _index_local_papers()

    tools = {}

    # --- query_papers ---
    def query_papers(params):
        keyword = params.get("keyword", "")
        category = params.get("category", "")
        source = params.get("source", "")
        max_results = params.get("max_results", 10)

        entries = _load_index()
        keyword_lower = keyword.lower()
        results = []

        for entry in entries:
            # Source filter
            if source and entry.get("source") != source:
                continue
            # Category filter
            if category and entry.get("category") != category:
                continue
            # Keyword search over title + abstract
            if keyword_lower:
                title = (entry.get("title") or "").lower()
                abstract = (entry.get("abstract") or "").lower()
                if keyword_lower not in title and keyword_lower not in abstract:
                    continue

            results.append(
                {
                    "paper_id": entry["paper_id"],
                    "title": entry.get("title", ""),
                    "abstract": (entry.get("abstract") or "")[:300],
                    "category": entry.get("category", ""),
                    "source": entry.get("source", ""),
                    "notes": entry.get("notes", ""),
                }
            )

            if len(results) >= max_results:
                break

        return json.dumps(results, indent=2)

    tools["query_papers"] = (
        {
            "name": "query_papers",
            "description": "Search stored papers in the local 5G paper collection. Case-insensitive keyword search over title and abstract. Optional category and source filters.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "keyword": {
                        "type": "string",
                        "description": "Search keyword (e.g. 'fuzzing', 'baseband', 'RRC'). Searches title + abstract.",
                    },
                    "category": {
                        "type": "string",
                        "description": "Filter by category (e.g. 'Fuzzing & Testing', 'Baseband Reverse Engineering'). Exact match.",
                    },
                    "source": {
                        "type": "string",
                        "description": "Filter by source (e.g. 'local').",
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum results (default 10)",
                    },
                },
            },
        },
        query_papers,
    )

    # --- read_paper ---
    def read_paper(params):
        paper_id = params["paper_id"]
        offset = params.get("offset", 0)
        max_chars = params.get("max_chars", 15000)

        text_path = os.path.join(PAPERS_TEXT_PATH, f"{_safe_paper_id(paper_id)}.txt")

        if not os.path.exists(text_path):
            # Check if text extraction failed
            entries = _load_index()
            for e in entries:
                if e["paper_id"] == paper_id:
                    if e.get("text_extraction_failed"):
                        return json.dumps(
                            {
                                "error": "Text extraction failed for this paper. Use the abstract from query_papers instead.",
                                "paper_id": paper_id,
                            }
                        )
                    break
            return json.dumps(
                {
                    "error": f"No text found for paper_id '{paper_id}'.",
                    "paper_id": paper_id,
                }
            )

        with open(text_path, "r") as f:
            full_text = f.read()

        total_chars = len(full_text)
        chunk = full_text[offset : offset + max_chars]

        return json.dumps(
            {
                "text": chunk,
                "offset": offset,
                "total_chars": total_chars,
                "has_more": (offset + max_chars) < total_chars,
            }
        )

    tools["read_paper"] = (
        {
            "name": "read_paper",
            "description": "Read extracted text from a stored paper. Supports chunked reading via offset/max_chars for long papers.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "paper_id": {
                        "type": "string",
                        "description": "Full paper ID including prefix (e.g. 'local:ransacked')",
                    },
                    "offset": {
                        "type": "integer",
                        "description": "Character offset to start reading from (default 0)",
                    },
                    "max_chars": {
                        "type": "integer",
                        "description": "Maximum characters to return (default 15000)",
                    },
                },
                "required": ["paper_id"],
            },
        },
        read_paper,
    )

    # --- list_paper_categories ---
    def list_paper_categories(params):
        entries = _load_index()
        counts = {}
        for entry in entries:
            cat = entry.get("category", "") or "uncategorized"
            counts[cat] = counts.get(cat, 0) + 1

        result = sorted(
            [{"category": cat, "count": count} for cat, count in counts.items()],
            key=lambda x: -x["count"],
        )
        return json.dumps(result, indent=2)

    tools["list_paper_categories"] = (
        {
            "name": "list_paper_categories",
            "description": "List all paper categories with paper counts. Helps discover what's available in the local 5G paper collection.",
            "input_schema": {
                "type": "object",
                "properties": {},
            },
        },
        list_paper_categories,
    )

    return tools
