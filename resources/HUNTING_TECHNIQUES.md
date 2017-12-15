# Hunting Techniques
A list of the most popular hunting techniques used to find evil.


## Searching
The simplest method of hunting, searching is the process of querying data for specific artifacts and
can be performed in many tools. Searching requires finely defined search criteria to prevent result
overload.[Sqrrl](https://sqrrl.com/media/Common-Techniques-for-Hunting.pdf)

| Strong | Weak |
|--------|---------|
| Targeted approach | Anomalies/Outliers | 
| Can be performed in many tools | Searching for general artifacts my produce far too many results |


## Clustering
Clustering is a statistical technique, often carried out with machine learning, that consists of
separating groups (or clusters) of similar data points based on certain characteristics out of a larger
set of data.[Sqrrl](https://sqrrl.com/media/Common-Techniques-for-Hunting.pdf) 
Differences with Grouping is that the task(categorization of data) itself is done by the algorithm, and the results must be interpreted by the hunter to understand what the individual clusters consists of. This is considered an unserpevised machine learning technique.

| Strong | Weak |
|--------|---------|
| Discovery of new patterns or structures in your data | Requires additional analysis | 


## Grouping
Grouping consists of taking a set of multiple unique artifacts and identifying when multiple of them
appear together based on certain criteria. The major difference between grouping and clustering is
that in grouping your input is an explicit set of items that are each already of interest. Discovered
groups within these items of interest may potentially represent a tool or a TTP that an attacker
might be using. An important aspect of using this technique consists of determining the specific
criteria used to group the items, such as events having occurred during a specific time window.[Sqrrl](https://sqrrl.com/media/Common-Techniques-for-Hunting.pdf)

| Strong | Weak |
|--------|---------|
| Identification of known TTPs | Anomalies/Outliers | 
 

## Stack Counting
Also known as stacking, this is one of the most common techniques carried out by hunters to
investigate a hypothesis. Stacking involves counting the number of occurrences for values of a
particular type, and analyzing the outliers or extremes of those results.[Sqrrl](https://sqrrl.com/media/Common-Techniques-for-Hunting.pdf)

| Strong | Weak |
|--------|---------|
| Anomalies/Outliers | Numbers do not stack very well |
| Rarity is suspicious | Hard to adapt to automated alerts |
| Easy to implement | Long tail of resutls can be difficult |


## Scatter Plots
Graphical technique used to analyze the relationship of two numeric variables. You can fit a linear regression to demonstrate the relationship making easier to identify an outlier. [SANSThreatHuntingSummit2017 - David J Bianco]

| Strong | Weak |
|--------|---------|
| Comparing numerical data on two axes | Working with non-numerical data |
| Malicious data violates clear correlation | when the variables on the two axes have weak/no correlation |
| When you need to establish whether a correlation even exits | Need to compare on more than two axes |


## Box Plots
In descriptive statistics, a box plot or boxplot is a convenient way of graphically depicting groups of numerical data through their quartiles. Box plots may also have lines extending vertically from the boxes (whiskers) indicating variability outside the upper and lower quartiles, hence the terms box-and-whisker plot and box-and-whisker diagram. [Wikipedia](https://en.wikipedia.org/wiki/Box_plot)
A box and whisker plot is developed from five statistics. [SANSThreatHuntingSummit2017 - David J Bianco]

* Minimum value – the smallest value in the data set
* Second quartile – the value below which the lower 25% of the data are contained
* Median value – the middle number in a range of numbers
* Third quartile – the value above which the upper 25% of the data are contained
* Maximum value – the largest value in the data set

| Strong | Weak |
|--------|---------|
| Quick visual representation of data shape and skew at large scale | High level summary view loses individual data points |
| Outliers are explicity shown |  |
| Outliers thresholds may be easily converted to signatures |  |


## Isolation Forests
Similar to clustering, but with a better anomaly detection capability. In trees you can set the depth (layers) of your trees to identify the anomalies. A good technique to find things that are not part of clusters. A form of unsupervised machine learning too. A tree in a forest is the result of iteratively splitting a dataset on random dimensions and their values until it cannot be splitted anymore. The average depth across all trees for each point reflects "outliers". [SANSThreatHuntingSummit2017 - David J Bianco]

| Strong | Weak |
|--------|---------|
| Can outperform other clustering mechanisms (Faster, lower memory requirements) | Dificult to visualize at high dimensions |


