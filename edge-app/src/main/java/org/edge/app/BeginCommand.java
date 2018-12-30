package org.edge.app;

//import org.apache.karaf.shell.commands.Command;
//import org.onosproject.cli.AbstractShellCommand;

import org.apache.karaf.shell.commands.Argument;
import org.apache.karaf.shell.commands.Command;
import org.onosproject.cli.AbstractShellCommand;

/*
public class BeginCommand {

}*/
@Command(scope = "onos", name = "begin", description = "Begin Experiment")
public class BeginCommand extends AbstractShellCommand {


    /*
    @Argument(index = 0, name = "attackType",
            description = "Type of attacks to simulate",
            required = true, multiValued = false)
    String attackType = null;
    */

    @Override
    protected void execute() {

        print("Begin experiment");
        //ReactiveForwarding.BEGIN = true;
        //ReactiveForwarding.ATTACK_TYPE = result;
    }

}



