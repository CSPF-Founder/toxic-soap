.PHONY: build run test clean docker-build docker-run docker-stop help

# Default target
help:
	@echo "Toxic SOAP - Makefile targets:"
	@echo "  build        - Build the application with Maven"
	@echo "  run          - Run the application locally"
	@echo "  test         - Run tests"
	@echo "  clean        - Clean build artifacts"
	@echo "  docker-build - Build Docker image"
	@echo "  docker-run   - Run with Docker Compose"
	@echo "  docker-stop  - Stop Docker containers"

# Maven build
build:
	mvn clean package -DskipTests

# Run locally
run: build
	java -jar target/toxic-soap-1.0.0.jar

# Run tests
test:
	mvn test

# Clean build artifacts
clean:
	mvn clean
	rm -rf target/

# Docker build
docker-build:
	docker build -t toxic-soap:latest .

# Docker run with compose
docker-run:
	docker compose up --build -d
	@echo "Toxic SOAP is starting..."
	@echo "Admin Panel: http://localhost:4040/admin"
	@echo "WSDL: http://localhost:4040/ws/banking?wsdl"

# Stop Docker
docker-stop:
	docker compose down

# Full rebuild and run
all: clean docker-run
