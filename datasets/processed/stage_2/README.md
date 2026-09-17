# Stage 2: Larger Feature-Compatible Aggregates

This stage is intentionally empty. Add larger datasets only after producing genuine MANTIS window-level features such as `unique_ports`, `packet_count`, and `pps`.

Every added dataset must have separate `train`, `validation`, and `test` files, source hashes, class counts, a duplicate check, and a zero-overlap check. A raw destination-port value must never be renamed to `unique_ports`.
