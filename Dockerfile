FROM golang:1.22.0-alpine

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Intentionally run as root initially, for demonstration of non-root user fix
# USER root # If you want to explicitly put USER root for POC
EXPOSE 8080

CMD ["go", "run", "main.go"]