# FAQ - よくある質問

## Q1. なぜHTTP/3 Datagramではなくストリームを使うのですか？

**A:** HTTP/3 Datagramはquic-go v0.58.0において、ローカルのDockerネットワークでも**75%のパケットロス**が発生します。ストリームは100%の信頼性を提供し、VPNユースケースでは性能への影響も無視できる程度です。

| 項目 | ストリーム | Datagram |
|------|-----------|----------|
| パケットロス | 0% | 75% |
| 信頼性 | 保証 | ベストエフォート |
| HOLブロッキング | わずか | なし |
| 実装の複雑さ | 低 | 高 |

---

## Q2. RFC 9484 (MASQUE) 標準に準拠していますか？

**A:** 部分的に準拠しています。使用している仕様：
- ✅ HTTP CONNECTメソッド
- ✅ `Protocol: connect-ip` ヘッダー
- ✅ QUIC/HTTP3トランスポート
- ❌ Datagramフレーミング（長さプレフィックス付きストリームで代替）

RFC 9484はDatagramを推奨していますが、必須ではありません。ストリームベースのアプローチは、Datagramサポートが成熟するまでの実用的な代替手段です。

---

## Q3. 75%のDatagramパケットロスの原因は何ですか？

**A:** quic-goの3つの主要な問題：

1. **サイレントドロップ**: `SendDatagram()`がパケットをドロップしても成功を返す
2. **積極的な輻輳制御**: localhostでもDatagramを抑制する
3. **固定バッファサイズ**: Datagramの送受信バッファを増やす方法がない

ペーシング、リトライロジック、ウィンドウチューニングを試しましたが、効果はありませんでした。

---

## Q4. 将来的にDatagramをサポートする予定はありますか？

**A:** はい、以下の条件が満たされれば：
- quic-goが設定可能なDatagramバッファサイズを公開
- Datagramに対する輻輳制御が調整可能になる
- エラー報告が改善される（明示的なドロップ通知）

現時点では、ストリームが本番環境に適した選択肢です。

---

## Q5. 長さプレフィックス付きフレーミングの仕組みは？

**A:** 各パケットに2バイトの長さヘッダーを付与します：

```
┌──────────────┬─────────────────────────┐
│ 長さ (u16)   │ IPパケット（可変長）    │
│ ビッグエンディアン │ IPv4/IPv6 + ペイロード │
└──────────────┴─────────────────────────┘
```

これにより、TLSレコードと同様に、HTTP/3ストリーム上でパケット境界を保持します。

---

## Q6. ストリームとDatagramの性能オーバーヘッドは？

**A:** テスト結果：
- **レイテンシ**: ~10-15ms RTTのオーバーヘッド（VPNとして許容範囲）
- **スループット**: 大きな差はなし
- **CPU**: ストリーム管理によりわずかに高い

信頼性の向上は、わずかなレイテンシ増加を大きく上回ります。

---

## Q7. 複数のクライアントを同時に実行できますか？

**A:** 現在、Relayはすべてのクライアントに**固定の仮想IP**（10.100.0.2）を割り当てるため、一度に1つのクライアントしか動作しません。

マルチクライアント対応には以下が必要です：
- 動的IPAM（IPアドレス管理）
- クライアントごとのセッション追跡
- ルーティングロジックの更新

これはPhase 3（Connector & Security）で計画されています。

---

## Q8. なぜネイティブ実行ではなくDockerを使うのですか？

**A:** 主な理由は2つ：

1. **ルーティングの分離**: ホスト上でのルーティングループを防ぐ
2. **権限の分離**: `privileged: true`の代わりに`NET_ADMIN`ケーパビリティを使用

Linux上でネイティブ実行も可能ですが、ルーティングテーブルの慎重な管理が必要です。

---

## Q9. 本番環境で使用できますか？

**A:** まだできません。不足している機能：

- ❌ 認証機能（mTLS/OIDC）
- ❌ マルチクライアント対応
- ❌ アクセス制御リスト（ACL）
- ❌ コネクションプーリング
- ❌ メトリクス/監視

これは、コアトンネリングメカニズムの**概念実証**です。

---

## Q10. パケットフローをデバッグするには？

**A:** 3つのアプローチ：

1. **ログを確認**: クライアント/リレーの両方がパケットルーティングをログ出力
   ```bash
   docker compose logs -f client relay
   ```

2. **TUNインターフェースを検査**:
   ```bash
   docker compose exec relay ip addr show tun0
   docker compose exec relay ip route
   ```

3. **NATを検証**:
   ```bash
   docker compose exec relay iptables -t nat -L -n -v
   ```

詳細なデバッグ手順は[packet-flow.md](packet-flow.md)を参照してください。

---

## Q11. UDPトラフィック（DNS、ゲームなど）は使えますか？

**A:** はい！トンネルはプロトコル非依存です。あらゆるIPトラフィックが動作します：
- ✅ ICMP（ping/traceroute）
- ✅ TCP（HTTP、SSHなど）
- ✅ UDP（DNS、QUICアプリ、ゲーム）

対象IP/CIDRを`TARGET_CIDRS`環境変数に追加するだけです。

---

## Q12. 最大パケットサイズ（MTU）は？

**A:** 現在、ClientとRelayのTUNインターフェースともに**1300バイト**です。

これはQUIC上でのフラグメンテーションを避けるための保守的な値です。以下で増やせます：
- `masque-client/main.go`: `MTU = 1300`
- `masque-relay/main.go`: `ServerMTU = 1300`

ただし、実際のネットワークでのパスMTU問題に注意してください。

---

## Q13. 従来のVPN（OpenVPN、WireGuard）との違いは？

| 機能 | このプロジェクト | WireGuard | OpenVPN |
|------|-----------------|-----------|---------|
| プロトコル | HTTP/3 (QUIC) | UDP | TCP/UDP |
| 暗号化 | TLS 1.3 | ChaCha20 | OpenSSL |
| ファイアウォール通過 | 優秀（443番ポート） | 不良 | 良好（TCP） |
| 性能 | 良好 | 優秀 | 普通 |
| 標準 | RFC 9484 (MASQUE) | RFC 8926 | プロプライエタリ |

**利点**: 企業プロキシを通過可能（HTTPSトラフィックに見える）

---

## Q14. なぜRust/C++ではなくGoを使うのですか？

**A:** 実用性のため：
- ✅ 優れたQUICライブラリ（quic-go）
- ✅ シンプルなTUN/TAPサポート（water）
- ✅ 高速な開発イテレーション
- ✅ クロスプラットフォーム（macOS/Linux）

性能はボトルネックではなく、QUICのオーバーヘッドが支配的です。

---

## Q15. MASQUEについてもっと学ぶには？

**A:** 主要なリソース：

- [RFC 9484 - Proxying IP in HTTP](https://www.rfc-editor.org/rfc/rfc9484.html) - コア仕様
- [RFC 9297 - HTTP/3 Datagrams](https://www.rfc-editor.org/rfc/rfc9297.html) - Datagramトランスポート
- [MASQUE IETF Working Group](https://datatracker.ietf.org/wg/masque/) - 最新の議論
- [AppleのiCloud Private Relay](https://www.apple.com/privacy/docs/iCloud_Private_Relay_Overview_Dec2021.PDF) - 実世界でのMASQUE展開事例

---

## さらにサポートが必要ですか？

- 📖 [パケットフロー詳細ドキュメント](packet-flow.md)を読む
- 💬 既存の[GitHubイシュー](https://github.com/yourusername/masque-playground/issues)を確認
- 🐛 詳細なログと共にバグを報告
