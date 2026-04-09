// Package frame implementa el formato de frame del protocolo DAVE (Discord Audio/Video
// End-to-End Encryption) versión 1.1.
//
// El formato de frame DAVE se define en protocol.md sección "Payload Format" y consiste
// en un frame de media interleaved (rangos cifrados y sin cifrar mezclados) seguido de
// un footer con datos suplementarios del protocolo.
//
// Estructura del frame:
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	/                                                               /
//	+            Interleaved protocol media frame (variable)        +
//	/                                                               /
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                                                               |
//	+          Truncated 8-byte AES-GCM authentication tag          +
//	|                                                               |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	/       Truncated ULEB128 synchronization nonce (variable)      /
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	/    Unencrypted range ULEB128 offset/length pairs (variable)   /
//	+               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	/               |  Suppl. Size  |      Magic Marker 0xFAFA      |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Campos del footer:
//   - Truncated tag: 8 bytes del tag de autenticación AES-128-GCM truncado
//     (protocol.md reduce de 16 a 8 bytes para minimizar overhead)
//   - Truncated nonce: nonce de 32 bits codificado en ULEB128, expandido a 96 bits
//     para operaciones AES-GCM (8 bytes en cero + 4 bytes del nonce)
//   - Unencrypted ranges: pares offset/length en ULEB128 que indican qué porciones
//     del frame interleaved permanecen en plaintext (necesario para que los
//     packetizers/depacketizers de WebRTC puedan procesar el frame)
//   - Suppl. Size: 1 byte que indica el tamaño de todo el contenido suplementario
//     (tag + nonce + ranges + este byte + magic marker)
//   - Magic Marker: 2 bytes 0xFAFA para detección rápida de frames DAVE
//
// Cifrado:
//   - Algoritmo: AES-128-GCM con tag truncado a 64 bits (8 bytes)
//   - El tag truncado cumple con NIST SP 800-38D Appendix C para tags de 64 bits
//   - Las zonas unencrypted se incluyen como Additional Authenticated Data (AAD)
//     para garantizar integridad sin cifrarlas (el SFU necesita leerlas)
//   - Todas las zonas cifradas se concatenan como un bloque continuo de plaintext
//     antes de cifrar, y se re-insertan interleaved en el frame original
//
// Referencias:
//   - protocol.md: "Payload Format", "Truncated authentication tag",
//     "Truncated synchronization nonce", "Unencrypted ranges", "ULEB128 Encoding"
package frame
