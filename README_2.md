## run docker

```bash
sudo docker build -t fpsi_opprf_exp_8 .
docker tag fpsi_opprf_exp_8:latest blueobsidian/fpsi_opprf_exp_8:latest
docker push blueobsidian/fpsi_opprf_exp_8:latest

sudo docker run -dit --name fpsi_opprf_exp_8 --cap-add=NET_ADMIN fpsi_opprf_exp_8:latest
```

```
tcset lo --rate 100Mbps --delay 80ms --overwrite
```

```
nohup ./shell_run_bench_fmap.sh > log 2>&1 &
```
