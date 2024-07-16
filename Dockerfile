# v25 is latest, will set to static version when image is available on dockerhub
FROM docker.io/bitnami/keycloak:latest

CMD ["kc.sh", "start-dev"]
