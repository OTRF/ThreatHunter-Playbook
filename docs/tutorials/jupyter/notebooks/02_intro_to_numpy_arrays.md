---
jupyter:
  jupytext:
    formats: md:myst
    text_representation:
      extension: .md
      format_name: myst
      format_version: '1.3'
      jupytext_version: 1.14.1
  kernelspec:
    display_name: Python
    language: python
    name: python3
---

# Introduction to Python NumPy Arrays
----------------------------------------------------------------------------

## Goals:
* Learn the basics of Python Numpy Arrays


**References:**
* http://www.numpy.org/
* https://docs.scipy.org/doc/numpy/user/quickstart.html
* https://www.datacamp.com/community/tutorials/python-numpy-tutorial
* https://blog.thedataincubator.com/2018/02/numpy-and-pandas/
* https://medium.com/@ericvanrees/pandas-series-objects-and-numpy-arrays-15dfe05919d7
* https://www.machinelearningplus.com/python/numpy-tutorial-part1-array-python-examples/
* https://towardsdatascience.com/a-hitchhiker-guide-to-python-numpy-arrays-9358de570121
* McKinney, Wes. Python for Data Analysis: Data Wrangling with Pandas, NumPy, and IPython. O'Reilly Media. Kindle Edition


## What is NumPy?
* NumPy is short for "Numerical Python" and it is a fundamental python package for scientific computing.
* It uses a high-performance data structure known as the **n-dimensional array** or **ndarray**, a multi-dimensional array object, for efficient computation of arrays and matrices.


## What is an Array?
* Python arrays are data structures that store data similar to a list, except the type of objects stored in them is constrained.
* Elements of an array are all of the same type and indexed by a tuple of positive integers.
* The python module array allows you to specify the type of array at object creation time by using a type code, which is a single character. You can read more about each type code here: https://docs.python.org/3/library/array.html?highlight=array#module-array 

```python
import array
```

```python
array_one = array.array('i',[1,2,3,4])
type(array_one)
```

```python
type(array_one[0])
```

## What is a NumPy N-Dimensional Array (ndarray)?
* It is an efficient multidimensional array providing fast array-oriented arithmetic operations.
* An ndarray as any other array, it is a container for homogeneous data (Elements of the same type)
* In NumPy, data in an ndarray is simply referred to as an array.
* As with other container objects in Python, the contents of an ndarray can be accessed and modified by indexing or slicing operations.
* For numerical data, NumPy arrays are more efficient for storing and manipulating data than the other built-in Python data structures. 

```python
import numpy as np
np.__version__
```

```python
list_one = [1,2,3,4,5]
```

```python
numpy_array = np.array(list_one)
type(numpy_array)
```

```python
numpy_array
```

## Advantages of NumPy Arrays


### Vectorized Operations
* The key difference between an array and a list is, arrays are designed to handle vectorized operations while a python list is not.
* NumPy operations perform complex computations on entire arrays without the need for Python for loops.
* In other words, if you apply a function to an array, it is performed on every item in the array, rather than on the whole array object.
* In a python list, you will have to perform a loop over the elements of the list.

```python
list_two = [1,2,3,4,5]
# The following will throw an error:
list_two + 2
```

* Performing a loop to add **2** to every integer in the list

```python
for index, item in enumerate(list_two):
    list_two[index] = item + 2
list_two
```

* With a NumPy array, you can do the same simply by doing the following:

```python
numpy_array
```

```python
numpy_array + 2
```

* Any arithmetic operations between equal-size arrays applies the operation element-wise: 

```python
numpy_array_one = np.array([1,2])
numpy_array_two = np.array([4,6])
```

```python
numpy_array_one + numpy_array_two
```

```python
numpy_array_one > numpy_array_two
```

### Memory.
* NumPy internally stores data in a contiguous block of memory, independent of other built-in Python objects.
* NumPy arrays takes significantly less amount of memory as compared to python lists.

```python
import numpy as np
import sys
```

```python
python_list = [1,2,3,4,5,6]
python_list_size = sys.getsizeof(1) * len(python_list)
python_list_size
```

```python
python_numpy_array = np.array([1,2,3,4,5,6])
python_numpy_array_size = python_numpy_array.itemsize * python_numpy_array.size
python_numpy_array_size
```

## Basic Indexing and Slicing 


### One Dimensional Array
* When it comes down to slicing and indexing, one-dimensional arrays are the same as python lists

```python
numpy_array
```

```python
numpy_array[1]
```

```python
numpy_array[1:4]
```

* You can slice the array and pass it to a variable. Remember that variables just reference objects.
* Any change that you make to the array slice, it will be technnically done on the original array object. Once again, variables just reference objects.

```python
numpy_array_slice = numpy_array[1:4]
numpy_array_slice
```

```python
numpy_array_slice[1] = 10
numpy_array_slice
```

```python
numpy_array
```

### Two-Dimensional Array
* In a two-dimensional array, elements of the array are one-dimensional arrays 

```python
numpy_two_dimensional_array = np.array([[1,2,3],[4,5,6],[7,8,9]])
```

```python
numpy_two_dimensional_array
```

```python
numpy_two_dimensional_array[1]
```

* Instead of looping to the one-dimensional arrays to access specific elements, you can just pass a second index value

```python
numpy_two_dimensional_array[1][2]
```

```python
numpy_two_dimensional_array[1,2]
```

* Slicing two-dimensional arrays is a little different than one-dimensional ones.

```python
numpy_two_dimensional_array
```

```python
numpy_two_dimensional_array[:1]
```

```python
numpy_two_dimensional_array[:2]
```

```python
numpy_two_dimensional_array[:3]
```

```python
numpy_two_dimensional_array[:2,1:]
```

```python
numpy_two_dimensional_array[:2,:1]
```

```python
numpy_two_dimensional_array[2][1:]
```

```python

```
