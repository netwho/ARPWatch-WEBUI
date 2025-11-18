.PHONY: build up down logs clean restart rebuild

build:
	docker compose build

up:
	docker compose up -d

down:
	docker compose down

logs:
	docker compose logs -f

restart:
	docker compose restart

rebuild:
	docker compose down
	docker compose build --no-cache
	docker compose up -d

clean:
	docker compose down -v
	docker system prune -f

# Start everything
start: build up
	@echo "Arpwatch UI is starting..."
	@echo "Frontend: http://localhost:3000"
	@echo "Backend API: http://localhost:8000"
	@echo "API Docs: http://localhost:8000/docs"

# View logs for all services
watch: logs

# Check status
status:
	docker compose ps

