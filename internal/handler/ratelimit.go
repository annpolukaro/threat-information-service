package handler

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type clientLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type RateLimiter struct {
	mu                sync.Mutex
	clients           map[string]*clientLimiter
	requestsPerSecond rate.Limit
	burst             int
	lastCleanup       time.Time
	trustedProxies    []*net.IPNet
}

func NewRateLimiter(requestsPerSecond rate.Limit, burst int) *RateLimiter {
	return &RateLimiter{
		clients:           make(map[string]*clientLimiter),
		requestsPerSecond: requestsPerSecond,
		burst:             burst,
		lastCleanup:       time.Now(),
	}
}

// SetTrustedProxies задаёт адреса доверенных reverse proxy.
// Только от этих адресов разрешено принимать X-Real-IP.
func (r *RateLimiter) SetTrustedProxies(cidrs []string) error {
	networks := make([]*net.IPNet, 0, len(cidrs))

	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil {
			return err
		}

		networks = append(networks, network)
	}

	r.mu.Lock()
	r.trustedProxies = networks
	r.mu.Unlock()

	return nil
}

// clientIP определяет адрес клиента.
// X-Real-IP учитывается только для доверенного прокси.
func (r *RateLimiter) clientIP(req *http.Request) string {
	remoteIP, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		remoteIP = req.RemoteAddr
	}

	parsedRemoteIP := net.ParseIP(remoteIP)
	if parsedRemoteIP == nil {
		return remoteIP
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	for _, network := range r.trustedProxies {
		if network.Contains(parsedRemoteIP) {
			forwardedIP := net.ParseIP(
				strings.TrimSpace(req.Header.Get("X-Real-IP")),
			)

			if forwardedIP != nil {
				return forwardedIP.String()
			}
		}
	}

	return parsedRemoteIP.String()
}

// getLimiter возвращает индивидуальный лимитер для IP.
func (r *RateLimiter) getLimiter(ip string) *rate.Limiter {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()

	// Удаляем клиентов, неактивных более 10 минут.
	// Проверяем необходимость очистки не чаще раза в минуту.
	if now.Sub(r.lastCleanup) > time.Minute {
		for clientIP, client := range r.clients {
			if now.Sub(client.lastSeen) > 10*time.Minute {
				delete(r.clients, clientIP)
			}
		}

		r.lastCleanup = now
	}

	if client, exists := r.clients[ip]; exists {
		client.lastSeen = now
		return client.limiter
	}

	limiter := rate.NewLimiter(r.requestsPerSecond, r.burst)

	r.clients[ip] = &clientLimiter{
		limiter:  limiter,
		lastSeen: now,
	}

	return limiter
}

// Middleware ограничивает количество запросов для каждого IP.
func (r *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ip := r.clientIP(req)

		limiter := r.getLimiter(ip)

		if !limiter.Allow() {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)

			_ = json.NewEncoder(w).Encode(map[string]string{
				"message": "Too many requests",
			})
			return
		}

		next.ServeHTTP(w, req)
	})
}
