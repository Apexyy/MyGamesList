import dotenv from 'dotenv'
dotenv.config() // DEVE essere la PRIMA cosa

import Fastify from 'fastify'
import fastifyCookie from 'fastify-cookie'
import fastifyJwt from 'fastify-jwt'
import bcrypt from 'bcrypt'
import { supabase } from './supabase.js'
import fetch from 'node-fetch'

const fastify = Fastify({ logger: true })

// --- Plugins ---
fastify.register(fastifyCookie)
fastify.register(fastifyJwt, {
    secret: process.env.JWT_SECRET,
    cookie: {
        cookieName: 'token', // nome del cookie da leggere
        signed: false        // true solo se vuoi firmarlo con fastify-cookie
    }
})


// --- Decorator per autenticazione ---
fastify.decorate('authenticate', async (request, reply) => {
    try {
        await request.jwtVerify() // ora leggerà automaticamente il cookie
        console.log('JWT Verified!')
    } catch (err) {
        console.log('JWT Verify Error:', err)
        return reply.code(401).send({ message: 'Token non valido' })
    }
})



// --- Registrazione ---
fastify.post('/register', async (request, reply) => {
    const { username, password } = request.body
    if (!username || !password) return reply.code(400).send({ message: 'username e password obbligatori' })

    const hashedPassword = await bcrypt.hash(password, 10)
    const { data, error } = await supabase
        .from('Users')
        .insert([{ username, password: hashedPassword }])
        .select()

    if (error) return reply.code(500).send({ message: 'Errore registrazione', error })

    return reply.code(201).send({ id: data[0].id, username: data[0].username })
})

// --- Login ---
fastify.post('/login', async (request, reply) => {
    const { username, password } = request.body
    if (!username || !password) return reply.code(400).send({ message: 'username e password obbligatori' })

    const { data, error } = await supabase
        .from('Users')
        .select('*')
        .eq('username', username)
        .limit(1)

    if (error || !data || data.length === 0) return reply.code(401).send({ message: 'Utente non trovato' })

    const user = data[0]
    const validPassword = await bcrypt.compare(password, user.password)
    if (!validPassword) return reply.code(401).send({ message: 'Password errata' })

    const token = fastify.jwt.sign({ id: user.id, username: user.username })

    reply
        .setCookie('token', token, {
            httpOnly: true,
            secure: false, // false in locale
            sameSite: 'Strict',
            path: '/',
            maxAge: 60 * 60 // 1 ora
        })
        .code(200)
        .send({ message: 'Login effettuato' })
})

// --- Logout ---
fastify.post('/logout', async (request, reply) => {
    reply.clearCookie('token').send({ message: 'Logout effettuato' })
})

// --- Rotta protetta ---
fastify.get('/users', { preValidation: [fastify.authenticate] }, async (request, reply) => {
    const { data, error } = await supabase
        .from('Users')
        .select('id, username, created_at')
        .order('created_at', { ascending: true })

    if (error) return reply.code(500).send({ message: 'Errore recupero utenti', error })
    return reply.send(data)
})

// Rotta protetta: cerca giochi per nome
fastify.get('/games', { preValidation: [fastify.authenticate] }, async (request, reply) => {
    try {
        const { search } = request.query

        if (!search) {
            return reply.code(400).send({ message: 'Parametro "search" obbligatorio' })
        }

        // URL API RAWG con ricerca per nome
        const API_URL = `https://api.rawg.io/api/games?search=${encodeURIComponent(search)}&page_size=40&key=${process.env.RAWG_KEY}`

        const response = await fetch(API_URL)
        if (!response.ok) {
            return reply.code(500).send({ message: 'Errore API giochi' })
        }

        const data = await response.json()

        // RAWG restituisce { results: [...] }
        return reply.send(data.results)
    } catch (err) {
        return reply.code(500).send({ message: 'Errore imprevisto', err })
    }
})

fastify.get('/game/:id', { preValidation: [fastify.authenticate] }, async (req, reply) => {
  const { id } = req.params

  if (!id) return reply.code(400).send({ message: 'Parametro "id" obbligatorio' })

  const API_URL = `https://api.rawg.io/api/games/${id}?key=${process.env.RAWG_KEY}`

  try {
    const response = await fetch(API_URL)
    if (!response.ok) return reply.code(response.status).send({ message: 'Gioco non trovato' })

    const data = await response.json()
    return reply.send(data)
  } catch (err) {
    return reply.code(500).send({ message: 'Errore imprevisto', err })
  }
})





// --- Avvio server ---
fastify.listen({ port: 3000 }, (err, address) => {
    if (err) {
        fastify.log.error(err)
        process.exit(1)
    }
    console.log(`Server in ascolto su ${address}`)
})
