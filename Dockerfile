FROM golang:1.23-alpine

WORKDIR /app

COPY . . 

RUN go build -o bannergrap bannerGrap.go

ENTRYPOINT ["./bannergrap"]


