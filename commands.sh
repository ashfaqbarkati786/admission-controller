docker rmi -f $(docker images -a -q)
docker build -t admission-controller .
docker tag admission-controller ashfaqbarkati786/adc
docker push ashfaqbarkati786/adc