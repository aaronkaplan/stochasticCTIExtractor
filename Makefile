all:
	docker build -t stochastic_alex:0.1 . --network=host && docker compose down && docker compose  --env-file .env up -d
