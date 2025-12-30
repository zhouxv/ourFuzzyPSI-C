## run docker

```bash
sudo docker build -t fpsi_prefix .
docker tag fpsi_prefix:latest blueobsidian/fpsi_prefix:latest
docker push blueobsidian/fpsi_prefix:latest

sudo docker run -dit --name fpsi_prefix --cap-add=NET_ADMIN fpsi_prefix:latest
```

```
tcset lo --rate 100Mbps --delay 80ms --overwrite
```

```
nohup ./shell_run_bench_fmap.sh > log 2>&1 &
```
