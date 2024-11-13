package net.maku.framework.common.utils;


import cn.hutool.core.collection.CollUtil;
import cn.hutool.core.collection.ListUtil;
import cn.hutool.core.lang.func.Func1;
import cn.hutool.core.util.ReferenceUtil;
import cn.hutool.core.util.ReflectUtil;
import cn.hutool.core.util.StrUtil;
import com.baomidou.mybatisplus.core.toolkit.LambdaUtils;
import com.baomidou.mybatisplus.core.toolkit.Wrappers;
import com.baomidou.mybatisplus.core.toolkit.support.LambdaMeta;
import com.baomidou.mybatisplus.core.toolkit.support.SFunction;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.apache.ibatis.reflection.property.PropertyNamer;

import java.awt.*;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.sql.Wrapper;
import java.util.*;
import java.util.List;
import java.util.function.Function;

/**
 * 树形结构工具类，如：菜单、机构等
 *
 * @author 阿沐 babamu@126.com
 * <a href="https://maku.net">MAKU</a>
 */
public class TreeUtils {

    /**
     * 根据pid，构建树节点
     */
    public static <T extends TreeNode<T>> List<T> build(List<T> treeNodes, Long pid) {
        // pid不能为空
        AssertUtils.isNull(pid, "pid");

        List<T> treeList = new ArrayList<>();
        for (T treeNode : treeNodes) {
            if (pid.equals(treeNode.getPid())) {
                treeList.add(findChildren(treeNodes, treeNode));
            }
        }

        return treeList;
    }

    /**
     * 查找子节点
     */
    private static <T extends TreeNode<T>> T findChildren(List<T> treeNodes, T rootNode) {
        for (T treeNode : treeNodes) {
            if (rootNode.getId().equals(treeNode.getPid())) {
                rootNode.getChildren().add(findChildren(treeNodes, treeNode));
            }
        }
        return rootNode;
    }

    /**
     * 构建树节点
     */
    public static <T extends TreeNode<T>> List<T> build(List<T> treeNodes) {
        List<T> result = new ArrayList<>();

        // list转map
        Map<Long, T> nodeMap = new LinkedHashMap<>(treeNodes.size());
        for (T treeNode : treeNodes) {
            nodeMap.put(treeNode.getId(), treeNode);
        }

        for (T node : nodeMap.values()) {
            T parent = nodeMap.get(node.getPid());
            if (parent != null && !(node.getId().equals(parent.getId()))) {
                parent.getChildren().add(node);
                continue;
            }

            result.add(node);
        }

        return result;
    }

    // 树构建方法，支持动态指定id, pid和子节点
    public static <T> List<T> build(List<T> treeNodes,
                                    SFunction<T, ?> getId,
                                    SFunction<T, ?> getPid,
                                    SFunction<T, List<T>> getChildren) {
        // 用一个 Map 存储节点，通过节点 ID 查找节点
        Map<Object, T> nodeMap = new HashMap<>();
        for (T node : treeNodes) {
            nodeMap.put(getId.apply(node), node);
        }

        List<T> rootNodes = new ArrayList<>();

        // 遍历节点，构建树形结构
        for (T node : treeNodes) {
            Object parentId = getPid.apply(node);  // 获取父节点 ID
            T parentNode = nodeMap.get(parentId);  // 查找父节点

            if (parentNode != null && !getId.apply(node).equals(getId.apply(parentNode))) {
                // 如果找到父节点且当前节点不等于父节点，添加到父节点的子节点列表
                List<T> children = getChildren.apply(parentNode);
                if (children == null) {
                    children = new ArrayList<>();  // 如果子节点列表为null，初始化一个空的列表
                    LambdaMeta meta = LambdaUtils.extract(getChildren);
//                    String fieldName = PropertyNamer.methodToProperty(meta.getImplMethodName());
                    String implMethodName = meta.getImplMethodName();
                    String sub = StrUtil.sub(implMethodName, 3, implMethodName.length());
                    ReflectUtil.invoke(parentNode,"set"+sub,children);
//                    setChildren(parentNode, children, getChildren); // 通过反射设置子节点
                }
                children.add(node);
            } else {
                // 如果没有父节点或者父节点是自己，则该节点为根节点
                rootNodes.add(node);
            }
        }

        return rootNodes;
    }


    public static void main(String[] args) {
        ArrayList<Menu> menus = CollUtil.newArrayList(
                new Menu("1", "0", "test1")
                , new Menu("2", "1", "test2")
                , new Menu("3", "1", "test4")
                , new Menu("4", "2", "test4")
        );
        List<Menu> build = build(menus, Menu::getId, Menu::getPid, Menu::getChilds);
        System.out.println();
//        SFunction<Menu, List<Menu>> getChilds = Menu::getChilds;
//        LambdaMeta meta = LambdaUtils.extract(getChilds);
//        System.out.println(meta.getImplMethodName());
//        String fieldName = PropertyNamer.methodToProperty(meta.getImplMethodName());
//        System.out.println(fieldName);
//
//        String implMethodName = meta.getImplMethodName();
//        StrUtil.sub(implMethodName, 3, implMethodName.length());

    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    static class Menu{
        private String id;
        private String pid;
        private String name;
        private List<Menu> childs;

        public Menu(String id, String pid, String name) {
            this.id = id;
            this.pid = pid;
            this.name = name;
        }
    }

}