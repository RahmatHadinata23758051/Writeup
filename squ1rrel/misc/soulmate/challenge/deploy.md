gcloud builds submit --tag us-central1-docker.pkg.dev/squ1rrelctf2026/ctf-26/soulmate:$(git rev-parse HEAD)
helm upgrade --install soulmate deployments/soulmate --namespace soulmate --create-namespace --set image.tag=$(git rev-parse HEAD)
