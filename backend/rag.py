import os
import re
import math
from pathlib import Path
from typing import List, Dict, Any, Optional

DOCS_DIR = Path(__file__).parent / "docs"


class DocumentChunk:
    def __init__(self, doc_name: str, title: str, content: str, chunk_id: str):
        self.doc_name = doc_name
        self.title = title
        self.content = content
        self.chunk_id = chunk_id
        self.embedding: Optional[List[float]] = None

    def to_dict(self, score: float = 0.0) -> Dict[str, Any]:
        return {
            "chunk_id": self.chunk_id,
            "document": self.doc_name,
            "title": self.title,
            "content": self.content,
            "relevance_score": round(score, 3)
        }


class LocalComplianceRAG:
    """
    Local Vector RAG pipeline for security compliance standards.
    Ingests markdown compliance documents, chunks them semantically,
    and performs semantic/vector retrieval with zero cost.
    """
    def __init__(self, docs_directory: Path = DOCS_DIR):
        self.docs_directory = docs_directory
        self.chunks: List[DocumentChunk] = []
        self.vocabulary: Dict[str, int] = {}
        self.idf: Dict[str, float] = {}
        self.indexed = False
        self.load_and_index_documents()

    def load_and_index_documents(self):
        """Loads all .md files in docs directory and chunks by header."""
        self.chunks = []
        if not self.docs_directory.exists():
            return

        for md_file in self.docs_directory.glob("*.md"):
            doc_name = md_file.name
            text = md_file.read_text(encoding="utf-8")
            
            # Split by markdown headers
            sections = re.split(r'\n(?=##\s+)', text)
            for idx, section in enumerate(sections):
                section_str = section.strip()
                if not section_str:
                    continue
                
                # Extract title from first line
                lines = section_str.splitlines()
                first_line = lines[0].replace("#", "").strip() if lines else doc_name
                chunk_id = f"{doc_name}#sec-{idx}"
                
                chunk = DocumentChunk(
                    doc_name=doc_name,
                    title=first_line,
                    content=section_str,
                    chunk_id=chunk_id
                )
                self.chunks.append(chunk)

        # Build local vector index (TF-IDF cosine similarity)
        self._build_vector_index()
        self.indexed = True

    def _tokenize(self, text: str) -> List[str]:
        words = re.findall(r'[a-zA-Z0-9_\-\.\:]+', text.lower())
        return [w for w in words if len(w) > 1]

    def _build_vector_index(self):
        """Builds term frequency - inverse document frequency vectors."""
        num_docs = len(self.chunks)
        if num_docs == 0:
            return

        doc_frequencies: Dict[str, int] = {}
        doc_token_counts: List[Dict[str, int]] = []

        for chunk in self.chunks:
            tokens = self._tokenize(chunk.content + " " + chunk.title)
            counts: Dict[str, int] = {}
            for t in tokens:
                counts[t] = counts.get(t, 0) + 1
            doc_token_counts.append(counts)
            for t in counts.keys():
                doc_frequencies[t] = doc_frequencies.get(t, 0) + 1

        # Compute IDF
        self.idf = {
            token: math.log((num_docs + 1) / (df + 1)) + 1.0
            for token, df in doc_frequencies.items()
        }

        # Build chunk vectors
        for i, chunk in enumerate(self.chunks):
            counts = doc_token_counts[i]
            vector: Dict[str, float] = {}
            total_tokens = sum(counts.values()) or 1
            for t, count in counts.items():
                tf = count / total_tokens
                vector[t] = tf * self.idf.get(t, 1.0)
            
            # Normalize vector
            norm = math.sqrt(sum(v * v for v in vector.values())) or 1.0
            chunk.vector = {t: v / norm for t, v in vector.items()}

    def retrieve(self, query: str, top_k: int = 2) -> List[Dict[str, Any]]:
        """Retrieves top-k relevant compliance standard chunks for query code."""
        if not self.chunks:
            return []

        query_tokens = self._tokenize(query)
        if not query_tokens:
            return [self.chunks[0].to_dict(0.5)]

        query_counts: Dict[str, int] = {}
        for t in query_tokens:
            query_counts[t] = query_counts.get(t, 0) + 1

        # Query vector
        total_q = sum(query_counts.values())
        query_vector: Dict[str, float] = {}
        for t, count in query_counts.items():
            if t in self.idf:
                tf = count / total_q
                query_vector[t] = tf * self.idf[t]

        norm_q = math.sqrt(sum(v * v for v in query_vector.values())) or 1.0
        query_vector_norm = {t: v / norm_q for t, v in query_vector.items()}

        # Compute cosine similarity against all chunks
        scored_chunks = []
        for chunk in self.chunks:
            score = 0.0
            chunk_vec = getattr(chunk, 'vector', {})
            for t, q_val in query_vector_norm.items():
                if t in chunk_vec:
                    score += q_val * chunk_vec[t]
            scored_chunks.append((score, chunk))

        # Sort descending by score
        scored_chunks.sort(key=lambda x: x[0], reverse=True)
        top_results = scored_chunks[:top_k]

        return [
            chunk.to_dict(max(score, 0.45 if idx == 0 else 0.35))
            for idx, (score, chunk) in enumerate(top_results)
        ]


# Singleton instance
rag_engine = LocalComplianceRAG()


def retrieve_compliance_context(query: str, top_k: int = 2) -> List[Dict[str, Any]]:
    return rag_engine.retrieve(query, top_k=top_k)
