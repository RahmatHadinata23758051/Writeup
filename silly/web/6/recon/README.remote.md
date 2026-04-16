# SnowBet - Blackjack SillyCTF Challenge

A full-featured blackjack gambling website built for CTF competitions.

## Features

- Full blackjack game mechanics (hit, stand, blackjack, push)
- User authentication (registration/login)
- SQLite database for persistence
- Real-time balance tracking
- Game history
- Beautiful casino-themed UI
- Fully Dockerized

## Tech Stack

- **Frontend**: React + TypeScript + Vite + Tailwind CSS
- **Backend**: Node.js + Express
- **Database**: SQLite (better-sqlite3)
- **Authentication**: JWT + bcrypt
- **Deployment**: Docker + Docker Compose

## Quick Start with Docker

1. Build and run the containers:
```bash
docker-compose up --build
```

2. Access the application:
   - Frontend: http://localhost:5173
   - Backend API: http://localhost:3001

3. Create an account and start playing!
   - New players receive $1000 starting balance

## Development Setup (Without Docker)

### Backend

```bash
cd server
npm install
npm start
```

The backend runs on port 3001.

### Frontend

```bash
npm install
npm run dev
```

The frontend runs on port 5173.

## Game Rules

- Dealer must hit on 16 and stand on 17
- Blackjack (21 with 2 cards) pays 2.5x
- Regular win pays 2x
- Push (tie) returns your bet
- Bust (over 21) loses your bet

## API Endpoints

- `POST /api/register` - Register new user
- `POST /api/login` - Login user
- `POST /api/logout` - Logout user
- `GET /api/me` - Get current user
- `POST /api/game/start` - Start new game
- `POST /api/game/hit` - Hit (draw another card)
- `POST /api/game/stand` - Stand (end turn)
- `GET /api/game/history` - Get game history

## Database Schema

### Users Table
- id (INTEGER PRIMARY KEY)
- username (TEXT UNIQUE)
- password (TEXT - bcrypt hashed)
- balance (REAL - default 1000.0)
- created_at (DATETIME)

### Games Table
- id (INTEGER PRIMARY KEY)
- user_id (INTEGER)
- bet_amount (REAL)
- result (TEXT)
- payout (REAL)
- player_hand (TEXT JSON)
- dealer_hand (TEXT JSON)
- created_at (DATETIME)

### Active Games Table
- id (INTEGER PRIMARY KEY)
- user_id (INTEGER UNIQUE)
- bet_amount (REAL)
- player_hand (TEXT JSON)
- dealer_hand (TEXT JSON)
- deck (TEXT JSON)
- created_at (DATETIME)

## CTF Notes

This application is designed for CTF competitions and includes:
- JWT authentication with a static secret (configurable)
- SQLite database with standard security
- Standard bcrypt password hashing
- CORS enabled for development

## License

MIT
