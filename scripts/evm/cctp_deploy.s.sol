pragma solidity ^0.7.6;

import "forge-std/Script.sol";
import "src/TokenMessenger.sol";
import "src/TokenMinter.sol";
import "src/MessageTransmitter.sol";
import "src/messages/Message.sol";

contract DeployScript is Script {
    address private attesterAddress;
    address private usdcContractAddress;
    address private usdcRemoteContractAddress;
    address private remoteTokenMessengerAddress;
    address private tokenControllerAddress;
    address private messageTransmitterPauserAddress;
    address private tokenMinterPauserAddress;
    address private messageTransmitterRescuerAddress;
    address private tokenMessengerRescuerAddress;
    address private tokenMinterRescuerAddress;

    uint32 private messageBodyVersion = 0;
    uint32 private version = 0;
    uint32 private domain;
    uint32 private remoteDomain;
    uint32 private maxMessageBodySize = 8192;
    uint256 private burnLimitPerMessage;

    uint256 private messageTransmitterDeployerPrivateKey;
    uint256 private tokenMessengerDeployerPrivateKey;
    uint256 private tokenMinterDeployerPrivateKey;
    uint256 private tokenControllerPrivateKey;

    /**
     * @notice deploys Message Transmitter
     * @param privateKey Private Key for signing the transactions
     * @return MessageTransmitter instance
     */
    function deployMessageTransmitter(uint256 privateKey)
        private
        returns (MessageTransmitter)
    {
        // Start recording transactions
        vm.startBroadcast(privateKey);

        // Deploy MessageTransmitter
        MessageTransmitter messageTransmitter = new MessageTransmitter(
            domain,
            attesterAddress,
            maxMessageBodySize,
            version
        );

        // Add Pauser
        messageTransmitter.updatePauser(messageTransmitterPauserAddress);

        // Add Rescuer
        messageTransmitter.updateRescuer(messageTransmitterRescuerAddress);

        // Stop recording transactions
        vm.stopBroadcast();
        return messageTransmitter;
    }

    /**
     * @notice deploys TokenMessenger
     * @param privateKey Private Key for signing the transactions
     * @param messageTransmitterAddress Message Transmitter Contract address
     * @return TokenMessenger instance
     */
    function deployTokenMessenger(
        uint256 privateKey,
        address messageTransmitterAddress
    ) private returns (TokenMessenger) {
        // Start recording transactions
        vm.startBroadcast(privateKey);

        // Deploy TokenMessenger
        TokenMessenger tokenMessenger = new TokenMessenger(
            messageTransmitterAddress,
            messageBodyVersion
        );

        // Add Rescuer
        tokenMessenger.updateRescuer(tokenMessengerRescuerAddress);

        // Stop recording transactions
        vm.stopBroadcast();

        return tokenMessenger;
    }

    /**
     * @notice deploys TokenMinter
     * @param privateKey Private Key for signing the transactions
     * @param tokenMessengerAddress TokenMessenger Contract address
     * @return TokenMinter instance
     */
    function deployTokenMinter(
        uint256 privateKey,
        address tokenMessengerAddress
    ) private returns (TokenMinter) {
        // Start recording transactions
        vm.startBroadcast(privateKey);

        // Deploy TokenMinter
        TokenMinter tokenMinter = new TokenMinter(tokenControllerAddress);

        // Add Local TokenMessenger
        tokenMinter.addLocalTokenMessenger(tokenMessengerAddress);

        // Add Pauser
        tokenMinter.updatePauser(tokenMinterPauserAddress);

        // Add Rescuer
        tokenMinter.updateRescuer(tokenMinterRescuerAddress);

        // Stop recording transactions
        vm.stopBroadcast();

        return tokenMinter;
    }

    /**
     * @notice add local minter to the TokenMessenger
     */
    function addMinterAddressToTokenMessenger(
        TokenMessenger tokenMessenger,
        uint256 privateKey,
        address minterAddress
    ) private {
        // Start recording transactions
        vm.startBroadcast(privateKey);

        tokenMessenger.addLocalMinter(minterAddress);

        // Stop recording transactions
        vm.stopBroadcast();
    }

    /**
     * @notice add usdc per-message burn limit for the TokenMinter
     */
    function setBurnLimitPerMessage(
        TokenMinter tokenMinter,
        uint256 privateKey
    ) private {
        // Start recording transactions
        vm.startBroadcast(privateKey);

        // Configure burn limit
        tokenMinter.setMaxBurnAmountPerMessage(
            usdcContractAddress,
            burnLimitPerMessage
        );

                // Stop recording transactions
        vm.stopBroadcast();
    }

    /**
     * @notice initialize variables from environment
     */
    function setUp() public {
        messageTransmitterDeployerPrivateKey = vm.envUint(
            "MESSAGE_TRANSMITTER_DEPLOYER_KEY"
        );
        tokenMessengerDeployerPrivateKey = vm.envUint(
            "TOKEN_MESSENGER_DEPLOYER_KEY"
        );
        tokenMinterDeployerPrivateKey = vm.envUint("TOKEN_MINTER_DEPLOYER_KEY");
        tokenControllerPrivateKey = vm.envUint("TOKEN_CONTROLLER_DEPLOYER_KEY");

        attesterAddress = vm.envAddress("ATTESTER_ADDRESS");
        usdcContractAddress = vm.envAddress("USDC_CONTRACT_ADDRESS");
        tokenControllerAddress = vm.envAddress("TOKEN_CONTROLLER_ADDRESS");
        burnLimitPerMessage = vm.envUint("BURN_LIMIT_PER_MESSAGE");
        
        domain = uint32(vm.envUint("DOMAIN"));

        messageTransmitterPauserAddress = vm.envAddress(
            "MESSAGE_TRANSMITTER_PAUSER_ADDRESS"
        );
        tokenMinterPauserAddress = vm.envAddress("TOKEN_MINTER_PAUSER_ADDRESS");

        messageTransmitterRescuerAddress = vm.envAddress(
            "MESSAGE_TRANSMITTER_RESCUER_ADDRESS"
        );
        tokenMessengerRescuerAddress = vm.envAddress(
            "TOKEN_MESSENGER_RESCUER_ADDRESS"
        );
        tokenMinterRescuerAddress = vm.envAddress(
            "TOKEN_MINTER_RESCUER_ADDRESS"
        );
    }

    /**
     * @notice main function that will be run by forge
     */
    function run() public {
        // Deploy MessageTransmitter
        MessageTransmitter messageTransmitter = deployMessageTransmitter(
            messageTransmitterDeployerPrivateKey
        );

        // Deploy TokenMessenger
        TokenMessenger tokenMessenger = deployTokenMessenger(
            tokenMessengerDeployerPrivateKey,
            address(messageTransmitter)
        );

        // Deploy TokenMinter
        TokenMinter tokenMinter = deployTokenMinter(
            tokenMinterDeployerPrivateKey,
            address(tokenMessenger)
        );

        // Add Local Minter
        addMinterAddressToTokenMessenger(
            tokenMessenger,
            tokenMessengerDeployerPrivateKey,
            address(tokenMinter)
        );

        // Set burn limit
        setBurnLimitPerMessage(
            tokenMinter, 
            tokenControllerPrivateKey
        );
    }
}
