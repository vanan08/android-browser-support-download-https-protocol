/*
 * CMC Browser for Android
 * 
 * Copyright (C) 2010 J. Devauchelle and contributors.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 3 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

package org.cmc.ui.runnables;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.net.SocketAddress;
import java.net.URL;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509TrustManager;

import org.cmc.model.items.DownloadItem;
import org.cmc.ui.activities.MainActivity;
import org.cmc.utils.IOUtils;
import android.content.SharedPreferences;
import android.os.Handler;
import android.os.Message;
import android.util.Log;
import android.webkit.CookieManager;

/**
 * Background downloader.
 */
public class DownloadRunnable implements Runnable {

	private static final int BUFFER_SIZE = 4096;

	private DownloadItem mParent;

	private boolean mAborted;

	/**
	 * Contructor.
	 * 
	 * @param parent
	 *            The item to download.
	 */
	public DownloadRunnable(DownloadItem parent) {
		mParent = parent;
		mAborted = false;
	}

	private Handler mHandler = new Handler() {

		public void handleMessage(Message msg) {
			mParent.onFinished();
		}
	};

	/**
	 * Compute the file name given the url.
	 * 
	 * @return The file name.
	 */
	private String getFileNameFromUrl() {
		String fileName = mParent.getUrl().substring(
				mParent.getUrl().lastIndexOf("/") + 1);

		int queryParamStart = fileName.indexOf("?");
		if (queryParamStart > 0) {
			fileName = fileName.substring(0, queryParamStart);
		}

		return fileName;
	}

	/**
	 * Get a file object representation of the file name, in th right folder of
	 * the SD card.
	 * 
	 * @return A file object.
	 */
	private File getFile() {

		File downloadFolder = IOUtils.getDownloadFolder();

		if (downloadFolder != null) {

			return new File(downloadFolder, getFileNameFromUrl());

		} else {
			mParent.setErrorMessage("Unable to get download folder from SD Card.");
			return null;
		}
	}

	@Override
	public void run() {

		File downloadFile = getFile();

		HttpURLConnection conn = null;

		if (downloadFile != null) {

			if (downloadFile.exists()) {
				downloadFile.delete();
			}

			BufferedInputStream bis = null;
			BufferedOutputStream bos = null;

			try {

				mParent.onStart();

				URL url = new URL(mParent.getUrl());
				CookieManager cookieManager = CookieManager.getInstance();
				String cookie = cookieManager.getCookie(url.getHost());

				String proxyHost = System.getProperty("http.proxyHost");
				String proxyPort = System.getProperty("http.proxyPort");

				if (proxyHost == null) {
					proxyHost = System.getProperty("https.proxyHost");
				}

				if (proxyPort == null) {
					proxyPort = System.getProperty("https.proxyPort");
				}

				Proxy p = null;
				if (proxyHost != null && !proxyHost.equals("")) {
					SocketAddress sa = new InetSocketAddress(proxyHost,
							Integer.parseInt(proxyPort));
					p = new Proxy(Proxy.Type.HTTP, sa);
					
				}

				SharedPreferences prefs = ((MainActivity)mParent.mContext).getPreferences(android.content.Context.MODE_PRIVATE); 
				final String proxyUser = prefs.getString("proxyUser", null);
				final String proxyPassword = prefs.getString("proxyPassword", null);
				
				
				if (url.getProtocol().toLowerCase().equals("https")) {
					trustAllHosts();
					HttpsURLConnection https = null;
					if (p != null) {
						Log.d("", "proxyHost1: " + proxyHost + " proxyPort: "
								+ proxyPort+ " proxyUser: "
								+ proxyUser);
						
						url = new URL(mParent.getUrl());
						if(proxyUser != null){
							Authenticator.setDefault(new Authenticator() {
								protected PasswordAuthentication getPasswordAuthentication() {
									return new PasswordAuthentication(
											proxyUser, proxyPassword.toCharArray());
								}
							});
						}
						
						https = (HttpsURLConnection) url.openConnection(p);
						
					} else {
						https = (HttpsURLConnection) url.openConnection();
					}
					https.setHostnameVerifier(DO_NOT_VERIFY);
					conn = https;
					Log.d("", "https");
				} else {
					if (p != null) {
						Log.d("", "proxyHost2: " + proxyHost + " proxyPort: "
								+ proxyPort);
						if(proxyUser != null){
							Authenticator.setDefault(new Authenticator() {
								protected PasswordAuthentication getPasswordAuthentication() {
									return new PasswordAuthentication(
											proxyUser, proxyPassword.toCharArray());
								}
							});
						}
						conn = (HttpURLConnection) url.openConnection(p);
					} else {
						conn = (HttpURLConnection) url.openConnection();
					}

				}

				conn.setRequestProperty("Cookie", cookie);

				// URLConnection conn = url.openConnection();

				InputStream is = conn.getInputStream();

				int size = conn.getContentLength();

				String fileHeader = conn.getHeaderField("Content-Disposition");
				if (fileHeader != null) {
					fileHeader = fileHeader.toLowerCase();
					int index = fileHeader.indexOf("filename");
					if (index != -1) {
						String name = fileHeader.substring(
								index + "filename".length() + 1,
								fileHeader.length());

						name = name.replace("'", "").replace("\"", "");

						if (downloadFile != null) {
							downloadFile = new File(
									IOUtils.getDownloadFolder(), name);
							mParent.updateFileName(name);
						}
					}
				}

				double oldCompleted = 0;
				double completed = 0;

				bis = new BufferedInputStream(is);
				bos = new BufferedOutputStream(new FileOutputStream(
						downloadFile));

				boolean downLoading = true;
				byte[] buffer = new byte[BUFFER_SIZE];
				int downloaded = 0;
				int read;

				while ((downLoading) && (!mAborted)) {

					if ((size - downloaded < BUFFER_SIZE)
							&& (size - downloaded > 0)) {
						buffer = new byte[size - downloaded];
					}

					read = bis.read(buffer);

					if (read > 0) {
						bos.write(buffer, 0, read);
						downloaded += read;

						completed = ((downloaded * 100f) / size);

					} else {
						downLoading = false;
					}

					// Notify each 5% or more.
					if (oldCompleted + 5 < completed) {
						mParent.onProgress((int) completed);
						oldCompleted = completed;
					}
				}

			} catch (MalformedURLException mue) {
				mParent.setErrorMessage(mue.getMessage());
			} catch (IOException ioe) {
				mParent.setErrorMessage(ioe.getMessage());
			} finally {

				if (bis != null) {
					try {
						bis.close();
					} catch (IOException ioe) {
						mParent.setErrorMessage(ioe.getMessage());
					}
				}
				if (bos != null) {
					try {
						bos.close();
					} catch (IOException ioe) {
						mParent.setErrorMessage(ioe.getMessage());
					}
				}
			}

			if (mAborted) {
				if (downloadFile.exists()) {
					downloadFile.delete();
				}
			}

		}

		mHandler.sendEmptyMessage(0);
	}

	/**
	 * Abort this download.
	 */
	public void abort() {
		mAborted = true;
	}

	/**
	 * always verify the host - dont check for certificate
	 * 
	 */
	final static HostnameVerifier DO_NOT_VERIFY = new HostnameVerifier() {
		public boolean verify(String hostname, SSLSession session) {
			return true;
		}
	};

	/**
	 * Trust every server - dont check for any certificate
	 */
	private static void trustAllHosts() {
		// Create a trust manager that does not validate certificate chains
		X509TrustManager[] trustAllCerts = new X509TrustManager[] { new X509TrustManager() {
			public X509Certificate[] getAcceptedIssuers() {
				return new java.security.cert.X509Certificate[] {};
			}

			public void checkClientTrusted(X509Certificate[] chain,
					String authType) throws CertificateException {
			}

			public void checkServerTrusted(X509Certificate[] chain,
					String authType) throws CertificateException {
			}
		} };

		// Install the all-trusting trust manager
		try {
			SSLContext sc = SSLContext.getInstance("TLS");
			sc.init(null, trustAllCerts, new java.security.SecureRandom());
			HttpsURLConnection
					.setDefaultSSLSocketFactory(sc.getSocketFactory());
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	class ProxyAuthenticator extends Authenticator {

		private String user, password;

		public ProxyAuthenticator(String user, String password) {
			this.user = user;
			this.password = password;
		}

		protected PasswordAuthentication getPasswordAuthentication() {
			return new PasswordAuthentication(user, password.toCharArray());
		}
	}
}
