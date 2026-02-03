#!/bin/bash

# Mesh-Chain SUMO Scenario Customization Tool
# Easily modify vehicle count, simulation time, and network

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUMO_DIR="${SCRIPT_DIR}/sumo"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

clear
echo -e "${BLUE}=================================================="
echo "  Mesh-Chain SUMO Scenario Customization"
echo "=================================================="
echo -e "${NC}"

# Main menu
while true; do
    echo ""
    echo -e "${CYAN}What would you like to customize?${NC}"
    echo "  1) Vehicle count (current: 360 cars/hour + 72 trucks/hour)"
    echo "  2) Simulation duration (current: 300 seconds)"
    echo "  3) Network type (current: Highway)"
    echo "  4) View current settings"
    echo "  5) Reset to defaults"
    echo "  6) Exit"
    echo ""
    read -p "Enter choice [1-6]: " choice

    case $choice in
        1)
            echo ""
            echo -e "${YELLOW}=== Customize Vehicle Count ===${NC}"
            echo "Current:"
            echo "  - Passenger cars: 360 vehicles/hour (1 every 2 seconds)"
            echo "  - Trucks: 72 vehicles/hour (1 every 10 seconds)"
            echo ""
            echo "Preset options:"
            echo "  1) Light traffic (180 cars/h, 36 trucks/h)"
            echo "  2) Medium traffic (360 cars/h, 72 trucks/h) [Default]"
            echo "  3) Heavy traffic (720 cars/h, 144 trucks/h)"
            echo "  4) Custom values"
            echo ""
            read -p "Select [1-4]: " traffic_choice

            case $traffic_choice in
                1)
                    CARS_PER_HOUR=180
                    TRUCKS_PER_HOUR=36
                    ;;
                2)
                    CARS_PER_HOUR=360
                    TRUCKS_PER_HOUR=72
                    ;;
                3)
                    CARS_PER_HOUR=720
                    TRUCKS_PER_HOUR=144
                    ;;
                4)
                    read -p "Enter cars per hour [1-1000]: " CARS_PER_HOUR
                    read -p "Enter trucks per hour [1-500]: " TRUCKS_PER_HOUR
                    ;;
                *)
                    echo -e "${RED}Invalid choice${NC}"
                    continue
                    ;;
            esac

            # Update highway.rou.xml
            echo -e "${YELLOW}Updating vehicle flows...${NC}"
            cat > "${SUMO_DIR}/highway.rou.xml" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!-- SUMO Route File: Highway Traffic (Customized) -->
<routes xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="http://sumo.dlr.de/xsd/routes_file.xsd">

    <!-- Vehicle types -->
    <vType id="car_passenger" accel="2.6" decel="4.5" sigma="0.5" length="4.5" minGap="2.5" maxSpeed="33.33" vClass="passenger" color="1,0,0"/>
    <vType id="car_truck" accel="1.3" decel="4.0" sigma="0.5" length="12.0" minGap="3.0" maxSpeed="27.78" vClass="truck" color="0,1,0"/>

    <!-- Route: Highway from start to end -->
    <route id="route_highway" edges="highway_main"/>

    <!-- Vehicle flows (Customized) -->
    <flow id="flow_passenger" type="car_passenger" route="route_highway" begin="0" end="200" vehsPerHour="${CARS_PER_HOUR}" departLane="best" departSpeed="max"/>
    <flow id="flow_truck" type="car_truck" route="route_highway" begin="5" end="205" vehsPerHour="${TRUCKS_PER_HOUR}" departLane="0" departSpeed="max"/>

</routes>
EOF
            echo -e "${GREEN}✓ Vehicle flows updated:${NC}"
            echo "  - Cars: ${CARS_PER_HOUR} vehicles/hour"
            echo "  - Trucks: ${TRUCKS_PER_HOUR} vehicles/hour"
            ;;

        2)
            echo ""
            echo -e "${YELLOW}=== Customize Simulation Duration ===${NC}"
            echo "Current: 300 seconds (5 minutes)"
            echo ""
            echo "Preset options:"
            echo "  1) Short (60 seconds / 1 minute)"
            echo "  2) Medium (300 seconds / 5 minutes) [Default]"
            echo "  3) Long (600 seconds / 10 minutes)"
            echo "  4) Very long (1800 seconds / 30 minutes)"
            echo "  5) Custom value"
            echo ""
            read -p "Select [1-5]: " duration_choice

            case $duration_choice in
                1) DURATION=60 ;;
                2) DURATION=300 ;;
                3) DURATION=600 ;;
                4) DURATION=1800 ;;
                5)
                    read -p "Enter duration in seconds [30-3600]: " DURATION
                    ;;
                *)
                    echo -e "${RED}Invalid choice${NC}"
                    continue
                    ;;
            esac

            # Update highway.sumo.cfg
            echo -e "${YELLOW}Updating simulation duration...${NC}"
            cat > "${SUMO_DIR}/highway.sumo.cfg" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!-- SUMO Configuration File (Customized) -->
<configuration xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="http://sumo.dlr.de/xsd/sumoConfiguration.xsd">

    <input>
        <net-file value="highway.net.xml"/>
        <route-files value="highway.rou.xml"/>
    </input>

    <time>
        <begin value="0"/>
        <end value="${DURATION}"/>
        <step-length value="0.1"/>
    </time>

    <processing>
        <collision.action value="warn"/>
        <collision.mingap-factor value="0"/>
        <time-to-teleport value="-1"/>
    </processing>

    <report>
        <verbose value="false"/>
        <no-step-log value="true"/>
    </report>

    <gui_only>
        <gui-settings-file value=""/>
    </gui_only>

</configuration>
EOF
            echo -e "${GREEN}✓ Simulation duration updated: ${DURATION} seconds ($((DURATION/60)) minutes)${NC}"
            ;;

        3)
            echo ""
            echo -e "${YELLOW}=== Customize Network Type ===${NC}"
            echo "Available networks:"
            echo "  1) Highway (3-lane, 5km) [Current]"
            echo "  2) Urban Grid (5x5 blocks, 500m each)"
            echo "  3) Intersection (4-way, traffic lights)"
            echo ""
            read -p "Select [1-3]: " network_choice

            case $network_choice in
                1)
                    echo -e "${GREEN}✓ Already using Highway network${NC}"
                    ;;
                2)
                    echo -e "${YELLOW}Generating urban grid network...${NC}"
                    if command -v netgenerate &> /dev/null; then
                        cd "${SUMO_DIR}"
                        netgenerate --grid \
                            --grid.number=5 \
                            --grid.length=500 \
                            --default.lanenumber=2 \
                            --output-file=urban.net.xml \
                            --no-turnarounds \
                            --tls.guess

                        # Update config
                        sed -i 's/highway.net.xml/urban.net.xml/g' highway.sumo.cfg

                        echo -e "${GREEN}✓ Urban grid network created${NC}"
                        echo -e "${YELLOW}Note: You may need to update routes for the new network${NC}"
                    else
                        echo -e "${RED}Error: netgenerate not found. Please install SUMO tools.${NC}"
                    fi
                    ;;
                3)
                    echo -e "${RED}Intersection network not yet implemented${NC}"
                    echo "Use 'netgenerate' manually to create custom networks"
                    ;;
                *)
                    echo -e "${RED}Invalid choice${NC}"
                    ;;
            esac
            ;;

        4)
            echo ""
            echo -e "${CYAN}=== Current Settings ===${NC}"
            echo ""

            # Parse current settings
            if [ -f "${SUMO_DIR}/highway.rou.xml" ]; then
                CARS=$(grep "flow_passenger" "${SUMO_DIR}/highway.rou.xml" | sed -n 's/.*vehsPerHour="\([0-9]*\)".*/\1/p')
                TRUCKS=$(grep "flow_truck" "${SUMO_DIR}/highway.rou.xml" | sed -n 's/.*vehsPerHour="\([0-9]*\)".*/\1/p')
                echo "Vehicle Flows:"
                echo "  - Passenger cars: ${CARS:-360} vehicles/hour"
                echo "  - Trucks: ${TRUCKS:-72} vehicles/hour"
            fi

            if [ -f "${SUMO_DIR}/highway.sumo.cfg" ]; then
                DUR=$(grep "<end value=" "${SUMO_DIR}/highway.sumo.cfg" | sed -n 's/.*value="\([0-9]*\)".*/\1/p')
                echo ""
                echo "Simulation:"
                echo "  - Duration: ${DUR:-300} seconds ($((${DUR:-300}/60)) minutes)"
                echo "  - Step length: 0.1 seconds"
            fi

            echo ""
            echo "Network:"
            echo "  - Type: Highway (3-lane, 5km)"
            echo "  - Max speed: 120 km/h"
            ;;

        5)
            echo ""
            echo -e "${YELLOW}Resetting to default settings...${NC}"

            # Reset routes
            cat > "${SUMO_DIR}/highway.rou.xml" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!-- SUMO Route File: Highway Traffic -->
<routes xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="http://sumo.dlr.de/xsd/routes_file.xsd">

    <!-- Vehicle types -->
    <vType id="car_passenger" accel="2.6" decel="4.5" sigma="0.5" length="4.5" minGap="2.5" maxSpeed="33.33" vClass="passenger" color="1,0,0"/>
    <vType id="car_truck" accel="1.3" decel="4.0" sigma="0.5" length="12.0" minGap="3.0" maxSpeed="27.78" vClass="truck" color="0,1,0"/>

    <!-- Route: Highway from start to end -->
    <route id="route_highway" edges="highway_main"/>

    <!-- Vehicle flows -->
    <flow id="flow_passenger" type="car_passenger" route="route_highway" begin="0" end="200" vehsPerHour="360" departLane="best" departSpeed="max"/>
    <flow id="flow_truck" type="car_truck" route="route_highway" begin="5" end="205" vehsPerHour="72" departLane="0" departSpeed="max"/>

</routes>
EOF

            # Reset config
            cat > "${SUMO_DIR}/highway.sumo.cfg" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!-- SUMO Configuration File -->
<configuration xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="http://sumo.dlr.de/xsd/sumoConfiguration.xsd">

    <input>
        <net-file value="highway.net.xml"/>
        <route-files value="highway.rou.xml"/>
    </input>

    <time>
        <begin value="0"/>
        <end value="300"/>
        <step-length value="0.1"/>
    </time>

    <processing>
        <collision.action value="warn"/>
        <collision.mingap-factor value="0"/>
        <time-to-teleport value="-1"/>
    </processing>

    <report>
        <verbose value="false"/>
        <no-step-log value="true"/>
    </report>

    <gui_only>
        <gui-settings-file value=""/>
    </gui_only>

</configuration>
EOF

            echo -e "${GREEN}✓ Settings reset to defaults${NC}"
            echo "  - Cars: 360/hour"
            echo "  - Trucks: 72/hour"
            echo "  - Duration: 300 seconds"
            ;;

        6)
            echo ""
            echo -e "${GREEN}Done! Run ./run_sumo_simple.sh to test your changes.${NC}"
            exit 0
            ;;

        *)
            echo -e "${RED}Invalid choice. Please enter 1-6.${NC}"
            ;;
    esac
done
