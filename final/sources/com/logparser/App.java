package com.logparser;

import com.drew.imaging.jpeg.JpegMetadataReader;
import com.drew.imaging.jpeg.JpegProcessingException;
import com.drew.metadata.Directory;
import com.drew.metadata.Tag;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Scanner;
import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.JDOMException;
import org.jdom2.input.SAXBuilder;
import org.jdom2.output.Format;
import org.jdom2.output.XMLOutputter;

public class App {
    public static Map parseLog(String line) {
        String[] strings = line.split("\\|\\|");
        Map map = new HashMap();
        map.put("status_code", Integer.valueOf(Integer.parseInt(strings[0])));
        map.put("ip", strings[1]);
        map.put("user_agent", strings[2]);
        map.put("uri", strings[3]);
        return map;
    }

    public static boolean isImage(String filename) {
        if (filename.contains(".jpg")) {
            return true;
        }
        return false;
    }

    public static String getArtist(String uri) throws IOException, JpegProcessingException {
        for (Directory dir : JpegMetadataReader.readMetadata(new File("/opt/panda_search/src/main/resources/static" + uri)).getDirectories()) {
            Iterator<Tag> it = dir.getTags().iterator();
            while (true) {
                if (it.hasNext()) {
                    Tag tag = it.next();
                    if (tag.getTagName() == "Artist") {
                        return tag.getDescription();
                    }
                }
            }
        }
        return "N/A";
    }

    public static void addViewTo(String path, String uri) throws JDOMException, IOException {
        SAXBuilder saxBuilder = new SAXBuilder();
        XMLOutputter xmlOutput = new XMLOutputter();
        xmlOutput.setFormat(Format.getPrettyFormat());
        File fd = new File(path);
        Document doc = saxBuilder.build(fd);
        Element rootElement = doc.getRootElement();
        for (Element el : rootElement.getChildren()) {
            if (el.getName() == "image" && el.getChild("uri").getText().equals(uri)) {
                Integer totalviews = Integer.valueOf(Integer.parseInt(rootElement.getChild("totalviews").getText()) + 1);
                System.out.println("Total views:" + Integer.toString(totalviews.intValue()));
                rootElement.getChild("totalviews").setText(Integer.toString(totalviews.intValue()));
                el.getChild("views").setText(Integer.toString(Integer.valueOf(Integer.parseInt(el.getChild("views").getText())).intValue() + 1));
            }
        }
        xmlOutput.output(doc, new BufferedWriter(new FileWriter(fd)));
    }

    public static void main(String[] args) throws JDOMException, IOException, JpegProcessingException {
        Scanner log_reader = new Scanner(new File("/opt/panda_search/redpanda.log"));
        while (log_reader.hasNextLine()) {
            String line = log_reader.nextLine();
            if (isImage(line)) {
                Map parsed_data = parseLog(line);
                System.out.println(parsed_data.get("uri"));
                String artist = getArtist(parsed_data.get("uri").toString());
                System.out.println("Artist: " + artist);
                addViewTo("/credits/" + artist + "_creds.xml", parsed_data.get("uri").toString());
            }
        }
    }
}
