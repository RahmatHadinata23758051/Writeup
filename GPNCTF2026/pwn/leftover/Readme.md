# Leftovers

This challenge ships a Java web service together with a custom JDK and an `AOT` cache:

- `leftovers.jar`
- `my-jdk/`
- `cache.aot`

The Java bytecode looks harmless at first glance. The interesting part is the runtime setup:

```bash
/my-jdk/bin/java -XX:AOTCache=cache.aot -jar leftovers.jar
```

So the real question is not only "what does the current JAR do?", but also "what stale code is still being pulled in from the code cache?".

## 1. Surface overview

The service exposes four endpoints:

- `GET /`
- `PUT /products/{name}`
- `GET /images/{name}`
- `POST /set-image-dir`

From the JAR, `POST /set-image-dir` should require the password `supersecret`, and `GET /images/{name}` should read files from an image directory after sanitizing the product name.

Running the service locally with and without `-XX:AOTCache=cache.aot` immediately shows a mismatch:

- without the cache, `supersecret` works
- with the cache, `supersecret` fails

That is the first strong sign that the stale compiled code does not match the current bytecode anymore.

## 2. Recovering the real password from the stale nmethod

I warmed up the relevant handlers locally and dumped the JIT/AOT code list with `jcmd`. That gave me a compiled entry for:

- `de.kitctf.gpn24.leftovers.Server.lambda$main$15`

This is the password check used by `POST /set-image-dir`.

Disassembling the verified entry with `gdb` showed that the stale version no longer compares against `"supersecret"`. Instead it:

1. builds a 12-character constant
2. lowercases/normalizes part of the user input
3. reverses the string
4. XORs it against the constant
5. compares the result

Inverting that transformation gives the real accepted password:

```text
algomaster99
```

That password works against the live target.

## 3. Turning `set-image-dir` into arbitrary file read

Once the old password is known, `POST /set-image-dir` becomes usable again.

The handler only checks that the supplied path exists and is a directory. It does not restrict where the directory can point. Because the service runs as root inside the container, `/proc/self/root` is especially useful: it gives a stable view of the container filesystem root.

So the exploit is:

1. Set the image directory to `/proc/self/root`
2. Create a product named `flag`
3. Request `GET /images/flag`

That works because the image path is resolved as:

```text
folderPath / sanitize(product.name)
```

With `folderPath = /proc/self/root`, the service opens:

```text
/proc/self/root/flag
```

which is the flag file in the container root.

## 4. Exploit flow

These are the only requests needed:

```http
POST /set-image-dir
{"password":"algomaster99","newPath":"/proc/self/root"}
```

```http
PUT /products/flag
{"product":{"name":"flag","quantity":1,"bestBefore":"2026-06-05T00:00:00","notAfter":"2026-06-06T00:00:00"},"imageUrl":null}
```

```http
GET /images/flag
```

The response returns the file contents directly, which yields:

```text
GPNCTF{13F7_OR_righT_COD3_cACHE_vaLIDAti0n_S4ys_600d_N1Gh7}
```

