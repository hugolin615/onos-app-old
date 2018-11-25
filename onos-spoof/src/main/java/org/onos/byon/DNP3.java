package org.onos.byon;

import org.onlab.packet.BasePacket;
import org.onlab.packet.Deserializer;
import org.onlab.packet.IPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Created by hugo on 9/1/16.
 */
public class DNP3 extends BasePacket {

    public static final int DNP3_HEADER_LENGTH = 10;
    private static Logger log = LoggerFactory.getLogger(DistributedNetworkStore.class);

    public static final int REQ_CONFIRM = 0x00;
    public static final int REQ_READ = 0x01;
    public static final int REQ_WRITE = 0X02;
    public static final int REQ_SELECT = 0X03;
    public static final int  REQ_OPERATE = 0X04;
    public static final int REQ_ENABLE_UNSOL = 0X14;
    public static final int REQ_DISABLE_UNSOL = 0X15;
    public static final int RESP = 0X81;
    public static final int RESP_UNSOL = 0X82;
    public static final int RESP_AUTHEN = 0X83;

    byte[]  magic = {0x05, 0x64};
    byte length = 0;
    byte ctrl = 0;
    byte[] dest = {0x00, 0x00};
    byte[] src = {0x00, 0x00};
    byte[] crc = {0x00, 0x00};

    byte tran = 0;
    byte app_ctrl = 0;
    byte fc = 0;
    byte[] resp_iid = null;
    byte[] payload = null;
    byte[] app_data = null;


    public DNP3(byte[] mHeader, byte[] mPayload){
        if (mHeader.length != DNP3_HEADER_LENGTH){
            System.out.println("invalid dnp3 header");
        }
        this.length = mHeader[2];
        this.ctrl = mHeader[3];
        System.arraycopy(mHeader, 4, this.dest, 0, 2);
        System.arraycopy(mHeader, 6, this.src, 0, 2);
        System.arraycopy(mHeader, 8, this.crc, 0, 2);
        if (mPayload.length > 0) {
            this.payload = new byte[mPayload.length];
            System.arraycopy(mPayload, 0, this.payload, 0, mPayload.length);
            this.tran = mPayload[0];
            this.app_ctrl = mPayload[1];
            this.fc = mPayload[2];
            if ((this.fc == 0x81) || (this.fc == 0x82) || (this.fc == 0x83)) {
                this.resp_iid = new byte[2];
                System.arraycopy(mPayload, 3, this.resp_iid, 0, 2);
            } else{
                this.resp_iid = null;
            }
        }
    }
    /*
    public DNP3(byte mLen, byte mCtrl, byte[] mDest, byte[] mSrc, byte mTran,
                     byte mAppctrl, byte mFc, byte[] mIid, byte[] mPayload){
        this.length = mLen;
        this.ctrl = mCtrl;
        System.arraycopy(mDest, 0, this.dest, 0, 2);
        System.arraycopy(mSrc, 0, this.src, 0, 2);
        this.tran = mTran;
        this.app_ctrl = mAppctrl;
        this.fc = mFc;
        System.arraycopy(mIid, 0, this.resp_iid, 0, 2);
        app_data = new byte[mPayload.length];
        System.arraycopy(mPayload, 0, app_data, 0, mPayload.length);

    }
    */

    @Override
    public byte[] serialize(){

        /*
        * Datalinke layer
        * 05 64 | len | Ctrl |  dst_lsb dst_msb |  src_lsb src_msb | crc |
        *
        *   */
        byte[] header = new byte[DNP3_HEADER_LENGTH];
        ByteBuffer header_buf = ByteBuffer.wrap(header);
        header_buf.put(this.magic);
        header_buf.put(this.length);
        header_buf.put(this.ctrl);
        header_buf.put(this.dest);
        header_buf.put(this.src);

        int crc_temp = computeCRC(Arrays.copyOfRange(header, 0, 8));
        //log.info(Integer.toHexString(dnp3B[8]) + Integer.toHexString(dnp3B[9]));
        byte crc_low = (byte)(crc_temp & 0x00FF);
        byte crc_high = (byte)((crc_temp >> 8) & 0x00FF);
        this.crc[0] = crc_low;
        this.crc[1] = crc_high;

        header_buf.put(this.crc);

        final byte[] data = new byte[DNP3_HEADER_LENGTH + this.payload.length];
        final ByteBuffer bb = ByteBuffer.wrap(data);
        bb.put(header);
        bb.put(this.payload);


        return data;
    }

    @Override
    public IPacket deserialize(final byte[] data, final int offset, final int length){

        this.length = data[offset + 2];
        this.ctrl = data[offset + 3];
        System.arraycopy(data, offset + 4, this.dest, 0, 2);
        System.arraycopy(data, offset + 6, this.src, 0, 2 );
        System.arraycopy(data, offset + 8, this.crc, 0, 2);
        if (length > DNP3_HEADER_LENGTH){

            System.arraycopy(data, offset + 10, this.payload, 0, length - DNP3_HEADER_LENGTH);
            this.tran = data[offset + 10];
            this.app_ctrl = data[offset + 11];
            this.fc = data[offset + 12];
            if ((this.fc == 0x81) || (this.fc == 0x82) || (this.fc == 0x83)) {
                this.resp_iid = new byte[2];
                System.arraycopy(data, offset + 13, this.resp_iid, 0, 2);
            } else{
                this.resp_iid = null;
            }
        }


        return this;
    }

    public static Deserializer<DNP3> deserializer() {
        return (data, offset, length) -> {
            byte[] mMagic = {0x05, 0x64};
            byte mLength = data[offset + 2];
            byte mCtrl = data[offset + 3];
            byte[] mDest = new byte[2];
            System.arraycopy(data, offset + 4, mDest, 0, 2);
            byte[] mSrc = new byte[2];
            System.arraycopy(data, offset + 6, mSrc, 0, 2);
            byte[] mCrc = new byte[2];
            System.arraycopy(data, offset + 8, mCrc, 0, 2);
            byte mTran = 0;
            byte mAppctrl = 0;
            byte mFc = 0;
            byte[] mPayload = null;
            byte[] mIid = null;

            if (length > DNP3_HEADER_LENGTH) {

                mPayload = new byte[length - DNP3_HEADER_LENGTH];
                System.arraycopy(data, offset + 10, mPayload, 0, length - DNP3_HEADER_LENGTH);
                mTran = data[offset + 10];
                mAppctrl = data[offset + 11];
                mFc = data[offset + 12];
                if ((mFc == 0x81) || (mFc == 0x82) || (mFc == 0x83)) {
                    System.arraycopy(data, offset + 13, mIid, 0, 2);
                }
            }
            //DNP3 dnp3 = new DNP3(mLength, mCtrl, mDest, mSrc, mCrc, mTran, mAppctrl, mFc, mIid, mPayload);
            byte[] header = new byte[DNP3_HEADER_LENGTH];
            ByteBuffer header_buf = ByteBuffer.wrap(header);
            header_buf.put(mMagic);
            header_buf.put(mLength);
            header_buf.put(mCtrl);
            header_buf.put(mDest);
            header_buf.put(mSrc);

            int crc_temp = computeCRC(Arrays.copyOfRange(header, 0, 8));
            //log.info(Integer.toHexString(dnp3B[8]) + Integer.toHexString(dnp3B[9]));
            byte crc_low = (byte) (crc_temp & 0x00FF);
            byte crc_high = (byte) ((crc_temp >> 8) & 0x00FF);

            header_buf.put(crc_low);
            header_buf.put(crc_high);

            DNP3 dnp3 = new DNP3(header, mPayload);
            return dnp3;
        };
    }

    private static int computeCRC(byte[] dataOctet) {

        //precompute crc tables
        int[] crc_table = new int[256];
        int crc;
        for (int i = 0; i < 256; i++) {
            crc = i;
            for (int j = 0; j < 8; j++) {
                if ((crc & 0x0001) != 0) {
                    crc = (crc >> 1) ^ 0xA6BC;//Generating polynomial.
                } else {
                    crc = crc >> 1;
                }
            }
            crc_table[i] = (crc);
        }

        //calculate crc
        crc = 0x0000;
        int index;
        for (int i = 0; i < dataOctet.length; i++) {
            index = (crc ^ dataOctet[i]) & 0x00FF;
            crc = crc_table[index] ^ (crc >> 8);
        }

        return ~crc & 0xFFFF;
    }

    public void set_data(byte[] mData){
        ////application layer
        this.app_data = new byte[mData.length];
        System.arraycopy(mData, 0, this.app_data, 0, mData.length);

        int data_size = this.app_data.length;
        int crc_temp = 0;
        byte crc_low = 0;
        byte crc_high = 0;
        int dnp3_payload_size = new Double(Math.ceil(data_size / 16.0 - 0.01)).intValue() * 2 + data_size;
        byte[] dnp3_payload = new byte[dnp3_payload_size];
        ByteBuffer dnp3_payload_buf = ByteBuffer.wrap(dnp3_payload);
        byte[] data_block = new byte[16];
        for (int i = 0; i < data_size; i = i + 16) {
            if ((i + 16) <= data_size) {
                data_block = Arrays.copyOfRange(this.payload, i, i + 16);
            } else {
                data_block = Arrays.copyOfRange(this.payload, i, data_size);
            }
            crc_temp = computeCRC(data_block);
            crc_low = (byte) (crc_temp & 0x00FF);
            crc_high = (byte) ((crc_temp >> 8) & 0x00FF);
            dnp3_payload_buf.put(data_block);
            dnp3_payload_buf.put(crc_low);
            dnp3_payload_buf.put(crc_high);
        }
        this.payload = new byte[dnp3_payload_size];
        System.arraycopy(dnp3_payload, 0, this.payload, 0, dnp3_payload_size);

    }

}
