FROM golang:1.24

COPY . .

RUN go build authenticator.go

EXPOSE 8080

CMD ["./authenticator"]