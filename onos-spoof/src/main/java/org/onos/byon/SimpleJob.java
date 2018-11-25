package org.onos.byon;

import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.quartz.Job;
import org.quartz.JobExecutionContext;
import org.quartz.JobExecutionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Created by hugo on 8/25/16.
 */
public class SimpleJob implements Job {

    //private Logger _log = LoggerFactory.getLogger(NetworkManager.SimpleJob.class);
    private static Logger log = LoggerFactory.getLogger(SimpleJob.class);

    //@Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    //protected NetworkStore store;

    //Empty constructor for job initialization

    public SimpleJob() {
    }


    public void execute(JobExecutionContext context)
            throws JobExecutionException {

        // This job simply prints out its job name and the
        // date and time that it is running
        //JobKey jobKey = context.getJobDetail().getKey();
        //_log.info("SimpleJob says: " + jobKey + " executing at " + new Date());
        //System.out.println("inside SimpleJob run");
        //log.info("inside SimpleJob run");
        //store.updateMeasure();

    }
}