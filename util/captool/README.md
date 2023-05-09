# Packet Capture Tool

This packet capture tool allows us to rapidly capture and anonymize packets
for flow analysis in relation to conjure stations.

This requires that the tool:

- read from multiple sources in parallel
- has access to GeoIP2 mmdbs to look up Country and ASN info
- deteministically anonymize client IPs and ports.
- write pcapng format with supplemental ASN/CC/subnet info in optional comments

Address anonymization is done by first determining what the addresses parent
subnet allocation is. We then replace the client address with a deterministically
chosen random addres by filling the host mask with bytes from an HMAC of the
flow tuple. we do the same for client ports. This allows us to ensure that the
separate packets within the same flow will still be linked, without
client-identifying information.

The Key for the HMAC is generated at runtime from the system CSPRNG and never
written to disk, only being stored in memory during the capture.

---

## Capture Parameters

Flows are captured from first SYN for TCP and from first seen for UDP.
