# Data Quality
 
One definition used the most about data quality is from Joseph M. Juran, author of [Juran’s Quality Handbook](https://www.amazon.com/Jurans-Quality-Handbook-Joseph-Juran/dp/007034003X/ref=pd_lpo_sbs_14_img_2?_encoding=UTF8&psc=1&refRID=GD9GCVSAQAHY7AC6XGC8), who quoted, in page 998,
> Data are of high quality if they are fit for their intended uses in operations, decision making and planning.

In other words, if data needed for a hunting engagement does not meet specific requirements defined by the hunt team, then the data is not considered quality data since it is affecting the intended purpose of it. I liked how Stephanie Zatyko from ["Experian Data Quality"](https://www.edq.com/blog/data-quality-vs-data-governance/) defined it by saying that if data was water, data quality ensures water is clean and does not get contaminated.

This activity is one of the most important ones, and it could actually define the success of your hunting engagement before it event starts. This is because if you identify that the data you will use for your hunt is not of quality, you will proactively identify obstacles that might affect the detection of adversarial techniques. Several teams ignore this activity and spend weeks trying to figure out why their query would not return any results. Others assume that their environment might not be compromised because their query did not return anything when in reality, they are not even collecting the right data in the first place.

## Data Quality Goals:

* Reduce the time hunters spend fixing and validating data issues increasing productivity during hunting engagements.
* Improve consistency across data sources to manipulate data more efficiently allowing more complex analytics that rely on several resources for extra context.
* Enhance automation flow

## Data Quality Dimensions:

Used to simplify the representation of measurable characteristics of data quality. There are several data quality dimensions defined out there that are useful, depending on the intended use of the data. However, for data that I need for a hunt program, I like to reference a few data quality dimensions from the ["DoD Core Set Of Data Quality Requirements"](https://medium.com/r/?url=http%3A%2F%2Fmitiq.mit.edu%2FICIQ%2FDocuments%2FIQ%2520Conference%25201996%2FPapers%2FDODGuidelinesonDataQualityManagement.pdf) A few of those Data Quality (DQ) dimensions could help your team categorize gaps found in data intended to be used for hunting purposes.

![](../images/DATA_QUALITY_DIMENSIONS.png)

Some of the DQ dimensions above might be hard to assess. Therefore, I recommend to at least cover **Completeness**, **Consistency** and **Timeliness**. Those will help you to start the conversation about your data with teams in charge of maintaining the data you use for hunting engagements.

## References

* http://library.ucmerced.edu/node/10249
