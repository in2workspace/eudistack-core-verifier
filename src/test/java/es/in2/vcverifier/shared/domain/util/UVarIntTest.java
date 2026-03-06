package es.in2.vcverifier.shared.domain.util;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class UVarIntTest {

    @Test
    void singleByteValue() {
        UVarInt uvi = new UVarInt(0);
        assertThat(uvi.getValue()).isZero();
        assertThat(uvi.getLength()).isEqualTo(1);
        assertThat(uvi.getBytes()).containsExactly((byte) 0);
    }

    @Test
    void singleByteMaxValue() {
        UVarInt uvi = new UVarInt(127);
        assertThat(uvi.getValue()).isEqualTo(127);
        assertThat(uvi.getLength()).isEqualTo(1);
        assertThat(uvi.getBytes()).containsExactly((byte) 0x7F);
    }

    @Test
    void twoByteValue() {
        UVarInt uvi = new UVarInt(128);
        assertThat(uvi.getValue()).isEqualTo(128);
        assertThat(uvi.getLength()).isEqualTo(2);
        assertThat(uvi.getBytes()).containsExactly((byte) 0x80, (byte) 0x01);
    }

    @Test
    void multicodecP256PublicKey() {
        // 0x1200 = 4608 is the multicodec for P-256 public key
        UVarInt uvi = new UVarInt(0x1200);
        assertThat(uvi.getValue()).isEqualTo(0x1200);
        assertThat(uvi.getLength()).isEqualTo(2);
    }

    @Test
    void largerValue() {
        UVarInt uvi = new UVarInt(300);
        assertThat(uvi.getValue()).isEqualTo(300);
        assertThat(uvi.getLength()).isEqualTo(2);
        assertThat(uvi.getBytes()).containsExactly((byte) 0xAC, (byte) 0x02);
    }

    @Test
    void toStringReturnsHex() {
        UVarInt uvi = new UVarInt(255);
        assertThat(uvi.toString()).isEqualTo("0xff");
    }

    @Test
    void toStringZero() {
        UVarInt uvi = new UVarInt(0);
        assertThat(uvi.toString()).isEqualTo("0x0");
    }
}
