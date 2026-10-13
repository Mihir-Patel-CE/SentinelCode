import { Review, ReviewListResponse, User, SampleSnippet, UserSettings, SupportedLanguage, LanguageCapability } from '../types';

const API_BASE = 'https://sentinelcode-1.onrender.com/api/v1';

class ApiService {
  private getToken(): string | null {
    return localStorage.getItem('sentinel_token');
  }

  public setToken(token: string): void {
    localStorage.setItem('sentinel_token', token);
  }

  public removeToken(): void {
    localStorage.removeItem('sentinel_token');
  }

  private async request<T>(endpoint: string, options: RequestInit & { timeoutMs?: number } = {}): Promise<T> {
    const headers = new Headers(options.headers || {});
    if (!headers.has('Content-Type') && !(options.body instanceof FormData)) {
      headers.set('Content-Type', 'application/json');
    }

    const token = this.getToken();
    if (token) {
      headers.set('Authorization', `Bearer ${token}`);
    }

    const controller = new AbortController();
    const timeoutMs = options.timeoutMs || 30000;
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch(`${API_BASE}${endpoint}`, {
        ...options,
        signal: options.signal || controller.signal,
        headers,
      });

      if (!response.ok) {
        let errorMessage = `HTTP Error ${response.status}`;
        try {
          const errorData = await response.json();
          errorMessage = errorData.detail || errorData.message || errorMessage;
        } catch {
          errorMessage = response.statusText || errorMessage;
        }
        throw new Error(errorMessage);
      }

      if (response.status === 204) {
        return {} as T;
      }

      return response.json();
    } catch (err: any) {
      if (err.name === 'AbortError') {
        throw new Error('Request timed out. Please check server availability and try again.');
      }
      throw err;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  // Auth
  async login(username_or_email: string, password: string): Promise<{ access_token: string; token_type: string }> {
    const data = await this.request<{ access_token: string; token_type: string }>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username_or_email, password }),
    });
    this.setToken(data.access_token);
    return data;
  }

  async demoLogin(): Promise<{ access_token: string; token_type: string }> {
    const data = await this.request<{ access_token: string; token_type: string }>('/auth/demo-login', {
      method: 'POST',
    });
    this.setToken(data.access_token);
    return data;
  }

  async register(email: string, username: string, password: string): Promise<User> {
    return this.request<User>('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, username, password }),
    });
  }

  async getMe(): Promise<User> {
    return this.request<User>('/auth/me');
  }

  // Reviews
  async analyzeCode(params: {
    title?: string;
    language: SupportedLanguage;
    code: string;
    enable_ai?: boolean;
  }): Promise<Review> {
    return this.request<Review>('/reviews/analyze', {
      method: 'POST',
      body: JSON.stringify(params),
    });
  }

  async listReviews(params: {
    page?: number;
    size?: number;
    language?: string;
    q?: string;
  } = {}): Promise<ReviewListResponse> {
    const query = new URLSearchParams();
    if (params.page) query.set('page', params.page.toString());
    if (params.size) query.set('size', params.size.toString());
    if (params.language) query.set('language', params.language);
    if (params.q) query.set('q', params.q);

    return this.request<ReviewListResponse>(`/reviews/?${query.toString()}`);
  }

  async getReview(id: number): Promise<Review> {
    return this.request<Review>(`/reviews/${id}`);
  }

  async deleteReview(id: number): Promise<void> {
    await this.request<void>(`/reviews/${id}`, { method: 'DELETE' });
  }

  getExportUrl(id: number): string {
    return `${API_BASE}/reviews/${id}/export`;
  }

  // Samples & Settings
  async getSamples(): Promise<SampleSnippet[]> {
    return this.request<SampleSnippet[]>('/samples/');
  }

  async getLanguages(): Promise<LanguageCapability[]> {
    return this.request<LanguageCapability[]>('/languages/');
  }

  async getSettings(): Promise<UserSettings> {
    return this.request<UserSettings>('/settings/');
  }

  async updateSettings(settings: Partial<UserSettings>): Promise<UserSettings> {
    return this.request<UserSettings>('/settings/', {
      method: 'PUT',
      body: JSON.stringify(settings),
    });
  }

  async checkHealth(): Promise<{ status: string }> {
    return this.request<{ status: string }>('/health');
  }
}

export const api = new ApiService();
