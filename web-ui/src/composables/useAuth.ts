import { ref, computed } from 'vue'
import { useRouter } from 'vue-router'
import { wsService } from '@/services/websocket'

// Global State
const username = ref<string | null>(null)
const isLoggedIn = ref(false)
const sessionChecked = ref(false)

export function useAuth() {
  const router = useRouter()

  const isAuthenticated = computed(() => isLoggedIn.value)

  function setAuthenticated(user: string) {
    username.value = user
    isLoggedIn.value = true

    localStorage.setItem('auth_username', user)
    localStorage.setItem('auth_logged_in', 'true')
    sessionChecked.value = true

    // 启动 WebSocket 连接
    wsService.start()
  }

  function clearAuthenticated() {
    username.value = null
    isLoggedIn.value = false
    sessionChecked.value = true
    localStorage.removeItem('auth_username')
    localStorage.removeItem('auth_logged_in')

    // 停止 WebSocket 连接
    wsService.stop()

  }

  async function logout() {
    try {
      await fetch('/auth/logout', {
        method: 'POST',
        credentials: 'same-origin',
      })
    } finally {
      clearAuthenticated()
    }

    // Redirect to login if using router
    if (router) {
      router.push('/login')
    } else {
      window.location.href = '/login'
    }
  }

  async function login(user: string, pass: string): Promise<boolean> {
    try {
      const response = await fetch('/auth/status', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'same-origin',
        body: JSON.stringify({ username: user, password: pass }),
      })

      if (response.ok) {
        setAuthenticated(user)
        return true
      } else {
        return false
      }
    } catch (e) {
      console.error('Login error', e)
      return false
    }
  }

  async function checkSession(): Promise<boolean> {
    if (sessionChecked.value) {
      return isLoggedIn.value
    }

    try {
      const response = await fetch('/auth/session', {
        credentials: 'same-origin',
      })
      if (!response.ok) {
        clearAuthenticated()
        return false
      }
      const data = await response.json()
      setAuthenticated(data.username)
      return true
    } catch (_error) {
      clearAuthenticated()
      return false
    }
  }

  return {
    username,
    isAuthenticated,
    login,
    logout,
    checkSession,
  }
}
