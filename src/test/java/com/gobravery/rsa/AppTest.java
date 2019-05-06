package com.gobravery.rsa;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.gobravery.rsa.jsbn.EncryptionService;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * Unit test for simple App.
 */
public class AppTest 
    extends TestCase
{
	private final static Logger logger = LoggerFactory.getLogger(App.class);
    /**
     * Create the test case
     *
     * @param testName name of the test case
     */
    public AppTest( String testName )
    {
        super( testName );
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite()
    {
        return new TestSuite( AppTest.class );
    }

    /**
     * Rigourous Test :-)
     */
    public void testApp()
    {
        assertTrue( true );
    }
    public void testJsbn(){
    	EncryptionService es=new EncryptionService();
        String mw="我的一家";
        logger.info("明文："+mw);
        String ens=es.en(mw);
        logger.info("密文："+ens);
        String jmw=es.de(ens);
        logger.info("解密："+jmw);
        logger.info("modu："+es.getModu());
        logger.info("公钥："+es.getPublicKey());
    }
}
