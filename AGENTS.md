# Repository Safety Boundary

1. This repository is a completely independent public open-source project.
2. Work only inside this repository's workspace.
3. Never access `E:\anshou-app`.
4. Never access `F:\anshouapp`.
5. Never read any other Git repository.
6. Never read any private repository.
7. Never access JKS files, private keys, passwords, tokens, credentials, or secret values from `.env` files.
8. Never commit Windows usernames, machine-specific absolute paths, private server domains, internal business information, or key material.
9. Test data must use only synthetic, mock, or otherwise public-safe fixtures.
10. Implement everything independently from public requirements and code contained in this repository.
