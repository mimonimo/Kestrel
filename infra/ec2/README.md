# infra/ec2 — 단일 EC2 운영 스택

`infra/` (ECS Fargate 풀스택) 의 비용 절감 대안. 데이터 영속성만 보장하면
되는 운영에 적합.

- 비용: 첫 해 ~$4/월, 이후 ~$17/월
- 운영 부담: SSM Session Manager 로 평소 손 안 댐
- 데이터 보존: 데이터 EBS 별도 + AWS Backup daily snapshot

자세한 진행은 [GUIDE.md](GUIDE.md) 참고.
