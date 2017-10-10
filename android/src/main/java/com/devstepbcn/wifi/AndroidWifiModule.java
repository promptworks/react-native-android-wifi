package com.devstepbcn.wifi;

import com.facebook.react.uimanager.*;
import com.facebook.react.bridge.*;
import com.facebook.systrace.Systrace;
import com.facebook.systrace.SystraceMessage;
// import com.facebook.react.LifecycleState;
import com.facebook.react.ReactInstanceManager;
import com.facebook.react.ReactRootView;
import com.facebook.react.modules.core.DefaultHardwareBackBtnHandler;
import com.facebook.react.modules.core.DeviceEventManagerModule;
import com.facebook.react.shell.MainReactPackage;
import com.facebook.soloader.SoLoader;

import android.content.ContentResolver;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiManager;
import android.net.wifi.WifiConfiguration;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.wifi.WifiInfo;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.BroadcastReceiver;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.provider.Settings.Secure;
import android.util.Log;
import android.widget.Toast;
import java.util.List;
import java.lang.reflect.Field;
import java.lang.Thread;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import static android.os.Build.VERSION.SDK_INT;
import static android.os.Build.VERSION_CODES.ICE_CREAM_SANDWICH_MR1;
import static android.os.Build.VERSION_CODES.JELLY_BEAN_MR1;

public class AndroidWifiModule extends ReactContextBaseJavaModule {

	//WifiManager Instance
	WifiManager wifi;

	//Constructor
	public AndroidWifiModule(ReactApplicationContext reactContext) {
		super(reactContext);
		wifi = (WifiManager)reactContext.getSystemService(Context.WIFI_SERVICE);
	}

	//Name for module register to use:
	@Override
	public String getName() {
		return "AndroidWifiModule";
	}

	//Method to load wifi list into string via Callback. Returns a stringified JSONArray
	@ReactMethod
	public void loadWifiList(Callback successCallback, Callback errorCallback) {
		try {
			List < ScanResult > results = wifi.getScanResults();
			JSONArray wifiArray = new JSONArray();

			for (ScanResult result: results) {
				JSONObject wifiObject = new JSONObject();
				if(!result.SSID.equals("")){
					try {
            wifiObject.put("SSID", result.SSID);
            wifiObject.put("BSSID", result.BSSID);
            wifiObject.put("capabilities", result.capabilities);
            wifiObject.put("frequency", result.frequency);
            wifiObject.put("level", result.level);
            wifiObject.put("timestamp", result.timestamp);
            //Other fields not added
            //wifiObject.put("operatorFriendlyName", result.operatorFriendlyName);
            //wifiObject.put("venueName", result.venueName);
            //wifiObject.put("centerFreq0", result.centerFreq0);
            //wifiObject.put("centerFreq1", result.centerFreq1);
            //wifiObject.put("channelWidth", result.channelWidth);
					} catch (JSONException e) {
          	errorCallback.invoke(e.getMessage());
					}
					wifiArray.put(wifiObject);
				}
			}
			successCallback.invoke(wifiArray.toString());
		} catch (IllegalViewOperationException e) {
			errorCallback.invoke(e.getMessage());
		}
	}

	//Method to check if wifi is enabled
	@ReactMethod
	public void isEnabled(Callback isEnabled) {
		isEnabled.invoke(wifi.isWifiEnabled());
	}

	//Method to connect/disconnect wifi service
	@ReactMethod
	public void setEnabled(Boolean enabled) {
		wifi.setWifiEnabled(enabled);
	}

	//Send the ssid and password of a Wifi network into this to connect to the network.
	//Example:  wifi.findAndConnect(ssid, password);
	//After 10 seconds, a post telling you whether you are connected will pop up.
	//Callback returns true if ssid is in the range
	@ReactMethod
	public void findAndConnect(String ssid, String password, Callback ssidFound) {
		List < ScanResult > results = wifi.getScanResults();
		boolean connected = false;
		for (ScanResult result: results) {
			String resultString = "" + result.SSID;
			if (ssid.equals(resultString)) {
				connected = connectTo(result, password, ssid);
			}
		}
		ssidFound.invoke(connected);
	}

	//Use this method to check if the device is currently connected to Wifi.
	@ReactMethod
	public void connectionStatus(Callback connectionStatusResult) {
		ConnectivityManager connManager = (ConnectivityManager) getReactApplicationContext().getSystemService(Context.CONNECTIVITY_SERVICE);
		NetworkInfo mWifi = connManager.getNetworkInfo(ConnectivityManager.TYPE_WIFI);
		if (mWifi.isConnected()) {
			connectionStatusResult.invoke(true);
		} else {
			connectionStatusResult.invoke(false);
		}
	}

	//Method to connect to WIFI Network
	public Boolean connectTo(ScanResult result, String password, String ssid) {
		//Make new configuration
		WifiConfiguration conf = new WifiConfiguration();
		
		if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
        conf.SSID = ssid;
    } else {
        conf.SSID = "\"" + ssid + "\"";
    }

		String capabilities = result.capabilities;
		
		if (capabilities.contains("WPA")  || 
          capabilities.contains("WPA2") || 
          capabilities.contains("WPA/WPA2 PSK")) {

	    // appropriate ciper is need to set according to security type used,
	    // ifcase of not added it will not be able to connect
	    conf.preSharedKey = "\"" + password + "\"";
	    
	    conf.allowedProtocols.set(WifiConfiguration.Protocol.RSN);
	    
	    conf.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.WPA_PSK);
	    
	    conf.status = WifiConfiguration.Status.ENABLED;
	    
	    conf.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.TKIP);
	    conf.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.CCMP);
	    
	    conf.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.WPA_PSK);
	    
	    conf.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.TKIP);
	    conf.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.CCMP);
	    
	    conf.allowedProtocols.set(WifiConfiguration.Protocol.RSN);
	    conf.allowedProtocols.set(WifiConfiguration.Protocol.WPA);

		}	else if (capabilities.contains("WEP")) {
			conf.wepKeys[0] = "\"" + password + "\"";
			conf.wepTxKeyIndex = 0;
			conf.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.NONE);
			conf.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.WEP40);

		} else {
			conf.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.NONE);
		}

		//Remove the existing configuration for this netwrok
		List<WifiConfiguration> mWifiConfigList = wifi.getConfiguredNetworks();

		int updateNetwork = -1;

		for(WifiConfiguration wifiConfig : mWifiConfigList){
			if(wifiConfig.SSID.equals(conf.SSID)){
				conf.networkId = wifiConfig.networkId;
				updateNetwork = wifi.updateNetwork(conf);
			}
		}

    // If network not already in configured networks add new network
		if ( updateNetwork == -1 ) {
      updateNetwork = wifi.addNetwork(conf);
      wifi.saveConfiguration();
		};

    if ( updateNetwork == -1 ) {
      return false;
    }

    boolean disconnect = wifi.disconnect();
		if ( !disconnect ) {
			return false;
		};

		boolean enableNetwork = wifi.enableNetwork(updateNetwork, true);
		if ( !enableNetwork ) {
			return false;
		};

		return true;
	}

	//Disconnect current Wifi.
	@ReactMethod
	public void disconnect() {
		wifi.disconnect();
	}

  // Checks whether the "Avoid poor networks" setting (named "Auto network switch" on
  // some Samsung devices) is enabled, which can in some instances interfere with Wi-Fi.
  @ReactMethod
  public void isWatchdogEnabled(final Callback callback) {
    Context context = getReactApplicationContext();
    boolean result = isWatchdogEnabled(context);
    callback.invoke(result);
  }

   private static boolean isWatchdogEnabled(Context context) {
     final int SETTING_UNKNOWN = -1;
     final int SETTING_ENABLED = 1;
     final String AVOID_POOR = "wifi_watchdog_poor_network_test_enabled";
     final String WATCHDOG_CLASS = "android.net.wifi.WifiWatchdogStateMachine";
     final String DEFAULT_ENABLED = "DEFAULT_POOR_NETWORK_AVOIDANCE_ENABLED";
     final ContentResolver contentResolver = context.getContentResolver();

     int result;

     if (SDK_INT == ICE_CREAM_SANDWICH_MR1 ) {
       result = Settings.Secure.getInt(contentResolver, AVOID_POOR, SETTING_UNKNOWN);
     } else if (SDK_INT >= JELLY_BEAN_MR1) {
       //Setting was moved from Secure to Global as of JB MR1
       result = Settings.Global.getInt(contentResolver, AVOID_POOR, SETTING_UNKNOWN);
     } else {
       //Poor network avoidance not introduced until ICS MR1
       //See android.provider.Settings.java
       return false;
     }

     //Exit here if the setting value is known
     if (result != SETTING_UNKNOWN) {
       return (result == SETTING_ENABLED);
     }

     //Setting does not exist in database, so it has never been changed.
     //It will be initialized to the default value.
     if (SDK_INT >= JELLY_BEAN_MR1) {
       //As of JB MR1, a constant was added to WifiWatchdogStateMachine to determine
       //the default behavior of the Avoid Poor Networks setting.
       try {
         //In the case of any failures here, take the safe route and assume the
         //setting is disabled to avoid disrupting the user with false information
         Class wifiWatchdog = Class.forName(WATCHDOG_CLASS);
         Field defValue = wifiWatchdog.getField(DEFAULT_ENABLED);
         if (!defValue.isAccessible()) {
           defValue.setAccessible(true);
         }
         return defValue.getBoolean(null);
       } catch (IllegalAccessException ex) {
         return false;
       } catch (NoSuchFieldException ex) {
         return false;
       } catch (ClassNotFoundException ex) {
         return false;
       } catch (IllegalArgumentException ex) {
         return false;
       }
     } else {
       //Prior to JB MR1, the default for the Avoid Poor Networks setting was
       //to enable it unless explicitly disabled
       return true;
     }
    }

	//This method will return current ssid
	@ReactMethod
	public void getSSID(final Callback callback) {
		WifiInfo info = wifi.getConnectionInfo();

		// This value should be wrapped in double quotes, so we need to unwrap it.
		String ssid = info.getSSID();
		if (ssid.startsWith("\"") && ssid.endsWith("\"")) {
			ssid = ssid.substring(1, ssid.length() - 1);
		}

		callback.invoke(ssid);
	}

	//This method will return the basic service set identifier (BSSID) of the current access point
	@ReactMethod
	public void getBSSID(final Callback callback) {
		WifiInfo info = wifi.getConnectionInfo();

		String bssid = info.getBSSID();

		callback.invoke(bssid.toUpperCase());
	}

	//This method will return current wifi signal strength
	@ReactMethod
	public void getCurrentSignalStrength(final Callback callback) {
		int linkSpeed = wifi.getConnectionInfo().getRssi();
		callback.invoke(linkSpeed);
	}
	//This method will return current IP
	@ReactMethod
	public void getIP(final Callback callback) {
		WifiInfo info = wifi.getConnectionInfo();
		String stringip=longToIP(info.getIpAddress());
		callback.invoke(stringip);
	}

	//This method will remove the wifi network as per the passed SSID from the device list
	@ReactMethod
	public void isRemoveWifiNetwork(String ssid, final Callback callback) {
    List<WifiConfiguration> mWifiConfigList = wifi.getConfiguredNetworks();
    for (WifiConfiguration wifiConfig : mWifiConfigList) {
				String comparableSSID = ('"' + ssid + '"'); //Add quotes because wifiConfig.SSID has them
				if(wifiConfig.SSID.equals(comparableSSID)) {
					wifi.removeNetwork(wifiConfig.networkId);
					wifi.saveConfiguration();
					callback.invoke(true);
					return;
				}
    }
		callback.invoke(false);
	}

	// This method is similar to `loadWifiList` but it forcefully starts the wifi scanning on android and in the callback fetches the list
	@ReactMethod
	public void reScanAndLoadWifiList(Callback successCallback, Callback errorCallback) {
		WifiReceiver receiverWifi = new WifiReceiver(wifi, successCallback, errorCallback);
   	getReactApplicationContext().getCurrentActivity().registerReceiver(receiverWifi, new IntentFilter(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION));
    wifi.startScan();
	}

	public static String longToIP(int longIp){
		StringBuffer sb = new StringBuffer("");
		String[] strip=new String[4];
		strip[3]=String.valueOf((longIp >>> 24));
		strip[2]=String.valueOf((longIp & 0x00FFFFFF) >>> 16);
		strip[1]=String.valueOf((longIp & 0x0000FFFF) >>> 8);
		strip[0]=String.valueOf((longIp & 0x000000FF));
		sb.append(strip[0]);
		sb.append(".");
		sb.append(strip[1]);
		sb.append(".");
		sb.append(strip[2]);
		sb.append(".");
		sb.append(strip[3]);
		return sb.toString();
	}

	class WifiReceiver extends BroadcastReceiver {

			private Callback successCallback;
			private Callback errorCallback;
			private WifiManager wifi;

			public WifiReceiver(final WifiManager wifi, Callback successCallback, Callback errorCallback) {
				super();
				this.successCallback = successCallback;
				this.errorCallback = errorCallback;
				this.wifi = wifi;
 			}

			// This method call when number of wifi connections changed
      public void onReceive(Context c, Intent intent) {
				// LocalBroadcastManager.getInstance(c).unregisterReceiver(this);
				c.unregisterReceiver(this);
				// getReactApplicationContext().getCurrentActivity().registerReceiver
				try {
					List < ScanResult > results = this.wifi.getScanResults();
					JSONArray wifiArray = new JSONArray();

					for (ScanResult result: results) {
						JSONObject wifiObject = new JSONObject();
						if(!result.SSID.equals("")){
							try {
		            wifiObject.put("SSID", result.SSID);
		            wifiObject.put("BSSID", result.BSSID);
		            wifiObject.put("capabilities", result.capabilities);
		            wifiObject.put("frequency", result.frequency);
		            wifiObject.put("level", result.level);
		            wifiObject.put("timestamp", result.timestamp);
							} catch (JSONException e) {
		          	this.errorCallback.invoke(e.getMessage());
								return;
							}
							wifiArray.put(wifiObject);
						}
					}
					this.successCallback.invoke(wifiArray.toString());
					return;
				} catch (IllegalViewOperationException e) {
					this.errorCallback.invoke(e.getMessage());
					return;
				}
      }
  }
}
