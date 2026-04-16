from sentence_transformers import SentenceTransformer

# Load model spesifik
model = SentenceTransformer('all-MiniLM-L6-v2')

# ECI codeword yang sudah di-normalize
codeword = "ambulant"

# Generate tensor embedding array
embedding = model.encode(codeword)

# Ekstrak index 0 dan bulatkan 4 angka di belakang koma (Variable Y)
var_y = round(embedding[0].item(), 4)

print(f"[*] Codeword  : {codeword}")
print(f"[*] Variable Y: {var_y:.4f}")
