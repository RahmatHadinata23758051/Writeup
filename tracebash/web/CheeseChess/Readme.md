# Writeup Cheese Chess

Aplikasi catur online berbasis React/Express yang menjalankan engine catur Stockfish di sisi client. Karena game state disinkronisasi lewat WebSocket dari client ke server, kita bisa memanipulasi jalannya permainan dan memenangkan game dengan mudah.

## Analisis & Kerentanan
1. File JavaScript client-side (`index.js`) di-obfuscate menggunakan `javascript-obfuscator` standar.
2. Setiap kali move dikirim ke server lewat WebSocket, client menyertakan signature `sig` untuk memvalidasi keaslian move.
3. Setelah deobfuscasi string bundle JS, fungsi `Ge` yang menghitung `sig` didefinisikan sebagai MD5 hash dari string template berikut:
   ```
   {sessionId}|{moveNumber}|{from}|{to}|{nonce}
   ```
   * `sessionId` diperoleh dari pesan `init` server.
   * `moveNumber` adalah index move (dimulai dari 0).
   * `from` dan `to` adalah posisi petak move.
   * `nonce` dikirim di awal pesan `init` (ter-encode Base64 `Y2gzM3N5X3MzY3IzdF8yMDI0` -> `ch33sy_s3cr3t_2024`).

## Eksploitasi
Karena server mempercayai move yang dikirim dari client selama signature MD5-nya cocok, kita bisa bermain di kedua sisi (White & Black) langsung lewat client WebSocket custom untuk memenangkan permainan dengan Scholar's Mate secara legal dalam 8 move:
1. Hubungkan ke WebSocket target `wss://web-cheese-chess.tracebash.xyz/ws`.
2. Dapatkan `sessionId` dan `nonce` dari server response `init`.
3. Kirim sequence move berikut dengan signature MD5 yang valid untuk setiap move:
   - Move 0 (w): e2 -> e4
   - Move 1 (b): e7 -> e5
   - Move 2 (w): a2 -> a3 (move useless legal)
   - Move 3 (b): d8 -> h4
   - Move 4 (w): h2 -> h3 (move useless legal)
   - Move 5 (b): f8 -> c5
   - Move 6 (w): a3 -> a4 (move useless legal)
   - Move 7 (b): h4 -> f2 (checkmate!)
4. Server memvalidasi checkmate dan mengembalikan flag.
