const API_BASE_URL = import.meta.env.VITE_API_URL || 'https://kestrel-ai-backend.onrender.com';

export async function analyzeCode(code, language = 'python', contextType = 'snippet') {
  const response = await fetch(`${API_BASE_URL}/api/analyze`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      code,
      language,
      context_type: contextType,
    }),
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || `Server error: ${response.status} ${response.statusText}`);
  }

  return await response.json();
}

export async function fetchSamples() {
  const response = await fetch(`${API_BASE_URL}/api/samples`);
  if (!response.ok) {
    throw new Error('Failed to load sample snippets.');
  }
  return await response.json();
}

export async function checkHealth() {
  const response = await fetch(`${API_BASE_URL}/api/health`);
  if (!response.ok) {
    throw new Error('Backend offline');
  }
  return await response.json();
}
