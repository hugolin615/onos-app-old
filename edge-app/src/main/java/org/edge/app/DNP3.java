package org.edge.app;

import org.onlab.packet.BasePacket;
import org.onlab.packet.Deserializer;
import org.onlab.packet.IPacket;
import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.util.Arrays;

import static org.slf4j.LoggerFactory.getLogger;

/**
 * Created by hugo on 9/1/16.
 */
public class DNP3 extends BasePacket {

    public static final int DNP3_HEADER_LENGTH = 10;
    private final Logger log = getLogger(getClass());

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
    byte appctrl = 0;
    byte fc = 0;
    byte[] respiid = null;
    byte[] payload = null;
    byte[] appdata = null;


    public DNP3(byte[] mHeader, byte[] mPayload) {
        if (mHeader.length != DNP3_HEADER_LENGTH) {
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
            this.appctrl = mPayload[1];
            this.fc = mPayload[2];
            if ((this.fc == 0x81) || (this.fc == 0x82) || (this.fc == 0x83)) {
                this.respiid = new byte[2];
                System.arraycopy(mPayload, 3, this.respiid, 0, 2);
            } else {
                this.respiid = null;
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
    public byte[] serialize() {

        /*
        * Datalinke layer
        * 05 64 | len | Ctrl |  dst_lsb dst_msb |  src_lsb src_msb | crc |
        *
        *   */
        byte[] header = new byte[DNP3_HEADER_LENGTH];
        ByteBuffer headerbuf = ByteBuffer.wrap(header);
        headerbuf.put(this.magic);
        headerbuf.put(this.length);
        headerbuf.put(this.ctrl);
        headerbuf.put(this.dest);
        headerbuf.put(this.src);

        int crctemp = computecrc(Arrays.copyOfRange(header, 0, 8));
        //log.info(Integer.toHexString(dnp3B[8]) + Integer.toHexString(dnp3B[9]));
        byte crclow = (byte) (crctemp & 0x00FF);
        byte crchigh = (byte) ((crctemp >> 8) & 0x00FF);
        this.crc[0] = crclow;
        this.crc[1] = crchigh;

        headerbuf.put(this.crc);

        final byte[] data = new byte[DNP3_HEADER_LENGTH + this.payload.length];
        final ByteBuffer bb = ByteBuffer.wrap(data);
        bb.put(header);
        bb.put(this.payload);


        return data;
    }

    /*
    @Override
    public IPacket deserialize(final byte[] data, final int offset, final int length) {

        this.length = data[offset + 2];
        this.ctrl = data[offset + 3];
        System.arraycopy(data, offset + 4, this.dest, 0, 2);
        System.arraycopy(data, offset + 6, this.src, 0, 2);
        System.arraycopy(data, offset + 8, this.crc, 0, 2);
        if (length > DNP3_HEADER_LENGTH) {

            System.arraycopy(data, offset + 10, this.payload, 0, length - DNP3_HEADER_LENGTH);
            this.tran = data[offset + 10];
            this.appctrl = data[offset + 11];
            this.fc = data[offset + 12];
            if ((this.fc == 0x81) || (this.fc == 0x82) || (this.fc == 0x83)) {
                this.respiid = new byte[2];
                System.arraycopy(data, offset + 13, this.respiid, 0, 2);
            } else {
                this.respiid = null;
            }
        }


        return this;
    }
    */

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
            ByteBuffer headerbuf = ByteBuffer.wrap(header);
            headerbuf.put(mMagic);
            headerbuf.put(mLength);
            headerbuf.put(mCtrl);
            headerbuf.put(mDest);
            headerbuf.put(mSrc);

            int crctemp = computecrc(Arrays.copyOfRange(header, 0, 8));
            //log.info(Integer.toHexString(dnp3B[8]) + Integer.toHexString(dnp3B[9]));
            byte crclow = (byte) (crctemp & 0x00FF);
            byte crchigh = (byte) ((crctemp >> 8) & 0x00FF);

            headerbuf.put(crclow);
            headerbuf.put(crchigh);

            DNP3 dnp3 = new DNP3(header, mPayload);
            return dnp3;
        };
    }

    private static int computecrc(byte[] dataoctet) {

        //precompute crc tables
        int[] crctable = new int[256];
        int crc;
        for (int i = 0; i < 256; i++) {
            crc = i;
            for (int j = 0; j < 8; j++) {
                if ((crc & 0x0001) != 0) {
                    crc = (crc >> 1) ^ 0xA6BC;
                } else {
                    crc = crc >> 1;
                }
            }
            crctable[i] = (crc);
        }

        //calculate crc
        crc = 0x0000;
        int index;
        for (int i = 0; i < dataoctet.length; i++) {
            index = (crc ^ dataoctet[i]) & 0x00FF;
            crc = crctable[index] ^ (crc >> 8);
        }

        return ~crc & 0xFFFF;
    }

    public void setdata(byte[] mData) {
        ////application layer
        this.appdata = new byte[mData.length];
        System.arraycopy(mData, 0, this.appdata, 0, mData.length);

        int datasize = this.appdata.length;
        int crctemp = 0;
        byte crclow = 0;
        byte crchigh = 0;
        int dnp3payloadsize = new Double(Math.ceil(datasize / 16.0 - 0.01)).intValue() * 2 + datasize;
        byte[] dnp3payload = new byte[dnp3payloadsize];
        ByteBuffer dnp3payloadbuf = ByteBuffer.wrap(dnp3payload);
        byte[] datablock = new byte[16];
        for (int i = 0; i < datasize; i = i + 16) {
            if ((i + 16) <= datasize) {
                datablock = Arrays.copyOfRange(this.payload, i, i + 16);
            } else {
                datablock = Arrays.copyOfRange(this.payload, i, datasize);
            }
            crctemp = computecrc(datablock);
            crclow = (byte) (crctemp & 0x00FF);
            crchigh = (byte) ((crctemp >> 8) & 0x00FF);
            dnp3payloadbuf.put(datablock);
            dnp3payloadbuf.put(crclow);
            dnp3payloadbuf.put(crchigh);
        }
        this.payload = new byte[dnp3payloadsize];
        System.arraycopy(dnp3payload, 0, this.payload, 0, dnp3payloadsize);

    }

}
