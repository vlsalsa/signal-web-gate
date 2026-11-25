# Pinned toolchain and minimal runtime. Review digest updates before upgrading.
FROM golang:1.27.3-bookworm@sha256:dc0963f32053e4bc451d24d87e3892d42d01021b61f093e98eb95c0352bb84b0 AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=readonly
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY *.go ./
RUN go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o /out/signal-gate . && mkdir -p /out/state

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build --chown=0:0 --chmod=0555 /out/signal-gate /gate/signal-gate
# Empty, gate-owned state dir so a named volume mounted here starts out writable.
COPY --from=build --chown=3006:3006 --chmod=0700 /out/state /gate/state
USER 3006:3006
EXPOSE 8080
ENTRYPOINT ["/gate/signal-gate"]
