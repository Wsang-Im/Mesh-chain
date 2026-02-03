//
// Mesh-Chain V2X Network Model for OMNET++
//
// Implements:
// - DSRC (802.11p) ~300m range
// - C-V2X PC5 ~1km range
// - 20% packet loss tolerance
// - Individual sig_req per witness
//

package meshchain;

import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.node.inet.ManetRouter;
import inet.physicallayer.ieee80211.packetlevel.Ieee80211ScalarRadioMedium;

//
// Vehicle node with V2X communication
//
module VehicleNode extends ManetRouter
{
    parameters:
        @display("i=block/wtx;is=vs");
        string vehicleId;
        string oem;  // Manufacturer for diversity
        double reputation = default(0.5);  // Initial reputation

        // V2X communication parameters
        wlan[0].radio.transmitter.power = 20mW;  // DSRC power
        wlan[0].radio.transmitter.communicationRange = 300m;

    gates:
        // No additional gates needed
}

//
// RSU (Road Side Unit) node
//
module RSUNode extends ManetRouter
{
    parameters:
        @display("i=device/antennatower;is=l");
        string rsuId;
        int anchorLevel = default(1);  // L1, L2, or L3

        // Higher power for RSU
        wlan[0].radio.transmitter.power = 100mW;
        wlan[0].radio.transmitter.communicationRange = 1000m;

    gates:
        // No additional gates needed
}

//
// Mesh-Chain V2X Network
//
network MeshChainNetwork
{
    parameters:
        int numVehicles = default(30);
        int numRSUs = default(3);

        @display("bgb=2000,2000");

    types:
        channel C extends DatarateChannel
        {
            delay = 1us;
            datarate = 6Mbps;  // 802.11p data rate
        }

    submodules:
        configurator: Ipv4NetworkConfigurator {
            @display("p=100,100;is=s");
        }

        radioMedium: Ieee80211ScalarRadioMedium {
            @display("p=100,200;is=s");
        }

        vehicle[numVehicles]: VehicleNode {
            @display("p=uniform(100,1900),uniform(100,1900)");
        }

        rsu[numRSUs]: RSUNode {
            @display("p=uniform(500,1500),uniform(500,1500)");
        }

    connections allowunconnected:
        // Wireless connections handled by radioMedium
}
