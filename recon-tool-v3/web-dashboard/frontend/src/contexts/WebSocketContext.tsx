import React, { createContext, useContext, useEffect, useRef, useState } from 'react'
import { io, Socket } from 'socket.io-client'
import toast from 'react-hot-toast'
import { useAuth } from './AuthContext'
import type { WebSocketMessage } from '../types/websocket'

interface WebSocketContextType {
  socket: Socket | null
  isConnected: boolean
  sendMessage: (message: any) => void
  lastMessage: WebSocketMessage | null
}

const WebSocketContext = createContext<WebSocketContextType | undefined>(undefined)

export function WebSocketProvider({ children }: { children: React.ReactNode }) {
  const [socket, setSocket] = useState<Socket | null>(null)
  const [isConnected, setIsConnected] = useState(false)
  const [lastMessage, setLastMessage] = useState<WebSocketMessage | null>(null)
  const { isAuthenticated, token } = useAuth()
  const reconnectAttempts = useRef(0)
  const maxReconnectAttempts = 5

  useEffect(() => {
    if (!isAuthenticated || !token) {
      // Disconnect if not authenticated
      if (socket) {
        socket.disconnect()
        setSocket(null)
        setIsConnected(false)
      }
      return
    }

    // Create WebSocket connection
    const newSocket = io('ws://localhost:8000', {
      auth: {
        token,
      },
      transports: ['websocket'],
      reconnection: true,
      reconnectionAttempts: maxReconnectAttempts,
      reconnectionDelay: 1000,
    })

    // Connection events
    newSocket.on('connect', () => {
      console.log('WebSocket connected')
      setIsConnected(true)
      reconnectAttempts.current = 0
      toast.success('Real-time connection established')
    })

    newSocket.on('disconnect', (reason) => {
      console.log('WebSocket disconnected:', reason)
      setIsConnected(false)
      if (reason === 'io server disconnect') {
        // Server disconnected, manual reconnection needed
        newSocket.connect()
      }
    })

    newSocket.on('connect_error', (error) => {
      console.error('WebSocket connection error:', error)
      reconnectAttempts.current++
      
      if (reconnectAttempts.current >= maxReconnectAttempts) {
        toast.error('Failed to establish real-time connection')
      }
    })

    // Message handlers
    newSocket.on('scan_progress', (data) => {
      const message: WebSocketMessage = {
        type: 'scan_progress',
        data,
        timestamp: new Date().toISOString(),
      }
      setLastMessage(message)
      
      // Show progress notification
      toast(`Scan ${data.scan_id}: ${data.progress}% complete`, {
        icon: '🔄',
      })
    })

    newSocket.on('scan_complete', (data) => {
      const message: WebSocketMessage = {
        type: 'scan_complete',
        data,
        timestamp: new Date().toISOString(),
      }
      setLastMessage(message)
      
      toast.success(`Scan ${data.scan_id} completed successfully!`)
    })

    newSocket.on('scan_error', (data) => {
      const message: WebSocketMessage = {
        type: 'scan_error',
        data,
        timestamp: new Date().toISOString(),
      }
      setLastMessage(message)
      
      toast.error(`Scan ${data.scan_id} failed: ${data.error}`)
    })

    newSocket.on('report_ready', (data) => {
      const message: WebSocketMessage = {
        type: 'report_ready',
        data,
        timestamp: new Date().toISOString(),
      }
      setLastMessage(message)
      
      toast.success(`Report ${data.report_id} is ready for download!`)
    })

    newSocket.on('system_notification', (data) => {
      const message: WebSocketMessage = {
        type: 'system_notification',
        data,
        timestamp: new Date().toISOString(),
      }
      setLastMessage(message)
      
      // Show system notification
      switch (data.level) {
        case 'info':
          toast(data.message, { icon: 'ℹ️' })
          break
        case 'warning':
          toast(data.message, { icon: '⚠️' })
          break
        case 'error':
          toast.error(data.message)
          break
      }
    })

    setSocket(newSocket)

    // Cleanup on unmount
    return () => {
      newSocket.disconnect()
    }
  }, [isAuthenticated, token])

  const sendMessage = (message: any) => {
    if (socket && isConnected) {
      socket.emit('message', message)
    } else {
      console.warn('Cannot send message: WebSocket not connected')
    }
  }

  const value: WebSocketContextType = {
    socket,
    isConnected,
    sendMessage,
    lastMessage,
  }

  return (
    <WebSocketContext.Provider value={value}>
      {children}
    </WebSocketContext.Provider>
  )
}

export function useWebSocket() {
  const context = useContext(WebSocketContext)
  if (context === undefined) {
    throw new Error('useWebSocket must be used within a WebSocketProvider')
  }
  return context
}
